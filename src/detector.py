"""Moteur de détection de menaces SSH pour Mini-SOC.

Ce module analyse les événements structurés issus de log_parser.py pour
identifier les attaques par force brute, le password spraying et les
compromissions de comptes potentielles selon le cadre MITRE ATT&CK.
"""

from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Tentatives d'authentification considérées comme des échecs
AUTH_FAILURE_TYPES: Set[str] = {
    "failed_password",
    "failed_publickey",
    "failed_keyboard_interactive",
    "invalid_user",
}

# Authentifications réussies
AUTH_SUCCESS_TYPES: Set[str] = {
    "accepted_password",
    "accepted_publickey",
}


@dataclass
class Alert:
    """Représente une alerte de sécurité structurée générée par le moteur."""

    timestamp: str
    rule_name: str
    severity: str  # "medium", "high", "critical"
    source_ip: str
    failed_attempts: int
    target_users: List[str]
    description: str
    mitre_technique: str

    def to_dict(self) -> Dict[str, Any]:
        """Convertit l'alerte en dictionnaire pour export ou intégration Pandas."""
        return asdict(self)


def _parse_timestamp(ts: Optional[Union[str, datetime.datetime]]) -> Optional[datetime.datetime]:
    """Convertit de manière sécurisée un timestamp (str ou datetime) en objet datetime."""
    if ts is None:
        return None
    if isinstance(ts, datetime.datetime):
        return ts
    if not isinstance(ts, str):
        return None

    cleaned = ts.strip()
    try:
        return datetime.datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%b %d %H:%M:%S"):
            try:
                return datetime.datetime.strptime(cleaned, fmt)
            except (ValueError, TypeError):
                continue
    return None


def _deduplicate_failure_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Évite le double comptage lors des tentatives avec un utilisateur invalide.

    Dans les journaux SSH Linux, une tentative avec un utilisateur inexistant génère
    souvent à la fois 'invalid_user' et 'failed_password for invalid user'
    pour la même tentative (même IP, même port ou horodatage quasi-identique).
    Cette fonction fusionne ces doublons en un seul événement d'échec.
    """
    deduped: List[Dict[str, Any]] = []
    seen_attempts: Set[Tuple[str, Optional[int], Optional[str], Optional[str]]] = set()

    for ev in events:
        event_type = ev.get("event_type")
        if event_type not in AUTH_FAILURE_TYPES:
            deduped.append(ev)
            continue

        ip = ev.get("source_ip") or ""
        port = ev.get("source_port")
        user = ev.get("username")
        ts = ev.get("timestamp")

        # Clé unique pour une tentative d'authentification donnée
        if port is not None:
            attempt_key = (ip, port, user, None)
        else:
            attempt_key = (ip, None, user, ts)

        if attempt_key in seen_attempts:
            # Si nous avons déjà enregistré l'échec (ex: invalid_user puis failed_password), ignorer le second
            continue

        seen_attempts.add(attempt_key)
        deduped.append(ev)

    return deduped


def _detect_brute_force(
    failure_events: List[Dict[str, Any]],
    window_minutes: int,
    threshold: int,
) -> List[Alert]:
    """Règle 1 — Détection de force brute SSH (MITRE ATT&CK T1110 / T1110.001).

    Regroupe les échecs par IP source et détecte si le nombre d'échecs dans une fenêtre
    temporelle dépasse le seuil (default: 5).
    Sévérité : 'medium' pour 5-9 échecs, 'high' pour 10 échecs ou plus.
    """
    alerts: List[Alert] = []
    window_delta = datetime.timedelta(minutes=window_minutes)

    # Regroupement des échecs par adresse IP
    events_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for ev in failure_events:
        ip = ev.get("source_ip")
        if ip:
            events_by_ip.setdefault(ip, []).append(ev)

    for ip, ip_events in events_by_ip.items():
        # Tri chronologique des événements de l'IP
        valid_events = []
        for ev in ip_events:
            dt = _parse_timestamp(ev.get("timestamp"))
            if dt:
                valid_events.append((dt, ev))
        valid_events.sort(key=lambda x: x[0])

        if not valid_events:
            continue

        # Consolidation par fenêtre glissante pour éviter les alertes redondantes
        active_burst: Optional[Dict[str, Any]] = None

        for dt, ev in valid_events:
            user = ev.get("username")

            if active_burst is None:
                # Recherche des événements dans la fenêtre [dt - window_delta, dt]
                window_matches = [
                    (w_dt, w_ev)
                    for (w_dt, w_ev) in valid_events
                    if dt - window_delta <= w_dt <= dt
                ]

                if len(window_matches) >= threshold:
                    users = sorted({w_ev.get("username") for _, w_ev in window_matches if w_ev.get("username")})
                    count = len(window_matches)
                    severity = "high" if count >= 10 else "medium"

                    active_burst = {
                        "first_dt": window_matches[0][0],
                        "last_dt": dt,
                        "count": count,
                        "users": set(users),
                        "severity": severity,
                    }
            else:
                # Si l'événement fait partie du même train d'attaques
                if dt - active_burst["last_dt"] <= window_delta:
                    active_burst["count"] += 1
                    active_burst["last_dt"] = dt
                    if user:
                        active_burst["users"].add(user)
                    if active_burst["count"] >= 10:
                        active_burst["severity"] = "high"
                else:
                    # Finalisation de l'alerte précédente
                    alerts.append(
                        Alert(
                            timestamp=active_burst["last_dt"].strftime("%Y-%m-%d %H:%M:%S"),
                            rule_name="SSH Brute Force",
                            severity=active_burst["severity"],
                            source_ip=ip,
                            failed_attempts=active_burst["count"],
                            target_users=sorted(active_burst["users"]),
                            description=(
                                f"Attaque par force brute détectée depuis l'IP {ip} : "
                                f"{active_burst['count']} échecs d'authentification en "
                                f"{int((active_burst['last_dt'] - active_burst['first_dt']).total_seconds() / 60) + 1} "
                                f"minute(s) ciblant les comptes : {', '.join(sorted(active_burst['users']))}."
                            ),
                            mitre_technique="T1110.001",
                        )
                    )
                    active_burst = None

        # Alerte en suspens à clore à la fin du flux
        if active_burst is not None:
            alerts.append(
                Alert(
                    timestamp=active_burst["last_dt"].strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="SSH Brute Force",
                    severity=active_burst["severity"],
                    source_ip=ip,
                    failed_attempts=active_burst["count"],
                    target_users=sorted(active_burst["users"]),
                    description=(
                        f"Attaque par force brute détectée depuis l'IP {ip} : "
                        f"{active_burst['count']} échecs d'authentification en "
                        f"{int((active_burst['last_dt'] - active_burst['first_dt']).total_seconds() / 60) + 1} "
                        f"minute(s) ciblant les comptes : {', '.join(sorted(active_burst['users']))}."
                    ),
                    mitre_technique="T1110.001",
                )
            )

    return alerts


def _detect_password_spraying(
    failure_events: List[Dict[str, Any]],
    window_minutes: int,
    user_threshold: int,
) -> List[Alert]:
    """Règle 2 — Détection de Password Spraying (MITRE ATT&CK T1110.003).

    Détecte une même IP source qui échoue à s'authentifier sur au moins N noms
    d'utilisateurs distincts au cours de la fenêtre temporelle.
    """
    alerts: List[Alert] = []
    window_delta = datetime.timedelta(minutes=window_minutes)

    events_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for ev in failure_events:
        ip = ev.get("source_ip")
        if ip:
            events_by_ip.setdefault(ip, []).append(ev)

    for ip, ip_events in events_by_ip.items():
        valid_events = []
        for ev in ip_events:
            dt = _parse_timestamp(ev.get("timestamp"))
            if dt and ev.get("username"):
                valid_events.append((dt, ev))
        valid_events.sort(key=lambda x: x[0])

        if not valid_events:
            continue

        active_spray: Optional[Dict[str, Any]] = None

        for dt, ev in valid_events:
            user = ev.get("username")

            if active_spray is None:
                # Fenêtre temporelle [dt - window_delta, dt]
                window_matches = [
                    (w_dt, w_ev)
                    for (w_dt, w_ev) in valid_events
                    if dt - window_delta <= w_dt <= dt
                ]
                distinct_users = {w_ev.get("username") for _, w_ev in window_matches if w_ev.get("username")}

                if len(distinct_users) >= user_threshold:
                    active_spray = {
                        "first_dt": window_matches[0][0],
                        "last_dt": dt,
                        "count": len(window_matches),
                        "users": set(distinct_users),
                    }
            else:
                if dt - active_spray["last_dt"] <= window_delta:
                    active_spray["count"] += 1
                    active_spray["last_dt"] = dt
                    if user:
                        active_spray["users"].add(user)
                else:
                    alerts.append(
                        Alert(
                            timestamp=active_spray["last_dt"].strftime("%Y-%m-%d %H:%M:%S"),
                            rule_name="SSH Password Spraying",
                            severity="high",
                            source_ip=ip,
                            failed_attempts=active_spray["count"],
                            target_users=sorted(active_spray["users"]),
                            description=(
                                f"Tentative de Password Spraying détectée depuis l'IP {ip} : "
                                f"{len(active_spray['users'])} comptes distincts ciblés "
                                f"({active_spray['count']} tentatives totales) : "
                                f"{', '.join(sorted(active_spray['users']))}."
                            ),
                            mitre_technique="T1110.003",
                        )
                    )
                    active_spray = None

        if active_spray is not None:
            alerts.append(
                Alert(
                    timestamp=active_spray["last_dt"].strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="SSH Password Spraying",
                    severity="high",
                    source_ip=ip,
                    failed_attempts=active_spray["count"],
                    target_users=sorted(active_spray["users"]),
                    description=(
                        f"Tentative de Password Spraying détectée depuis l'IP {ip} : "
                        f"{len(active_spray['users'])} comptes distincts ciblés "
                        f"({active_spray['count']} tentatives totales) : "
                        f"{', '.join(sorted(active_spray['users']))}."
                    ),
                    mitre_technique="T1110.003",
                )
            )

    return alerts


def _detect_success_after_failures(
    events: List[Dict[str, Any]],
    lookback_minutes: int,
    fail_threshold: int,
) -> List[Alert]:
    """Règle 3 — Connexion SSH réussie après des échecs répétés (MITRE ATT&CK T1110).

    Détecte une authentification réussie précédée d'au moins fail_threshold (default: 5)
    échecs d'authentification depuis la même IP au cours des lookback_minutes précédentes.
    Classé en sévérité 'critical'.
    """
    alerts: List[Alert] = []
    lookback_delta = datetime.timedelta(minutes=lookback_minutes)

    # Séparation et indexation temporelle des échecs et des succès
    failures_by_ip: Dict[str, List[Tuple[datetime.datetime, Dict[str, Any]]]] = {}
    successes: List[Tuple[datetime.datetime, Dict[str, Any]]] = []

    for ev in events:
        event_type = ev.get("event_type")
        ip = ev.get("source_ip")
        dt = _parse_timestamp(ev.get("timestamp"))

        if not ip or not dt:
            continue

        if event_type in AUTH_FAILURE_TYPES:
            failures_by_ip.setdefault(ip, []).append((dt, ev))
        elif event_type in AUTH_SUCCESS_TYPES:
            successes.append((dt, ev))

    # Tri chronologique des succès
    successes.sort(key=lambda x: x[0])

    for succ_dt, succ_ev in successes:
        succ_ip = succ_ev.get("source_ip")
        succ_user = succ_ev.get("username") or "unknown"

        ip_failures = failures_by_ip.get(succ_ip, [])
        # Filtrer les échecs survenus dans la fenêtre précédant immédiatement le succès
        recent_failures = [
            (f_dt, f_ev)
            for (f_dt, f_ev) in ip_failures
            if (succ_dt - lookback_delta) <= f_dt <= succ_dt
        ]

        if len(recent_failures) >= fail_threshold:
            targeted_users = sorted({f_ev.get("username") for _, f_ev in recent_failures if f_ev.get("username")})
            if succ_user not in targeted_users and succ_user != "unknown":
                targeted_users.append(succ_user)

            alerts.append(
                Alert(
                    timestamp=succ_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="Successful Login After Multiple Failures",
                    severity="critical",
                    source_ip=succ_ip,
                    failed_attempts=len(recent_failures),
                    target_users=targeted_users,
                    description=(
                        f"Connexion SSH réussie pour le compte '{succ_user}' depuis l'IP {succ_ip}, "
                        f"immédiatement précédée de {len(recent_failures)} échec(s) d'authentification "
                        f"au cours des {lookback_minutes} dernières minutes. "
                        f"Comportement suspect requérant une levée de doute SOC "
                        f"(indicateur d'une potentielle compromission d'identifiants)."
                    ),
                    mitre_technique="T1110",
                )
            )

    return alerts


def detect_threats(
    events: Union[List[Dict[str, Any]], Any],
    brute_force_window_minutes: int = 5,
    brute_force_threshold: int = 5,
    spray_window_minutes: int = 15,
    spray_user_threshold: int = 5,
    compromise_window_minutes: int = 15,
    compromise_fail_threshold: int = 5,
) -> List[Dict[str, Any]]:
    """Fonction principale du moteur de détection Mini-SOC.

    Analyse les événements SSH pour y identifier des attaques par force brute,
    password spraying ou réussites suspectes après échecs.

    Args:
        events: Liste de dictionnaires d'événements (issus de parse_log_file)
                ou un DataFrame Pandas.
        brute_force_window_minutes: Fenêtre d'agrégation force brute (1, 5 ou 15 min, défaut: 5).
        brute_force_threshold: Seuil d'échecs pour déclencher l'alerte force brute (défaut: 5).
        spray_window_minutes: Fenêtre d'analyse password spraying (défaut: 15 min).
        spray_user_threshold: Nombre minimal d'utilisateurs distincts ciblés (défaut: 5).
        compromise_window_minutes: Fenêtre d'observation avant succès (défaut: 15 min).
        compromise_fail_threshold: Nombre minimal d'échecs préalables (défaut: 5).

    Returns:
        Liste d'alertes structurées sous forme de dictionnaires, triées par date croissante.
    """
    # 1. Normalisation de l'entrée (compatible listes et DataFrames Pandas)
    if hasattr(events, "to_dict"):
        raw_events: List[Dict[str, Any]] = events.to_dict(orient="records")
    elif isinstance(events, list):
        raw_events = events
    else:
        return []

    if not raw_events:
        return []

    # Filtrer les événements inconnus, vides ou sans timestamp
    clean_events: List[Dict[str, Any]] = []
    for ev in raw_events:
        if not isinstance(ev, dict):
            continue
        if ev.get("event_type") in ("unknown", "empty", "comment"):
            continue
        if not ev.get("timestamp"):
            continue
        clean_events.append(ev)

    # 2. Déduplication des échecs d'authentification
    deduped_events = _deduplicate_failure_events(clean_events)

    # Extraction des seuls échecs pour les règles 1 et 2
    failure_events = [
        ev for ev in deduped_events
        if ev.get("event_type") in AUTH_FAILURE_TYPES
    ]

    all_alerts: List[Alert] = []

    # 3. Exécution des règles de détection
    # Règle 1 : Force brute
    all_alerts.extend(
        _detect_brute_force(
            failure_events=failure_events,
            window_minutes=brute_force_window_minutes,
            threshold=brute_force_threshold,
        )
    )

    # Règle 2 : Password spraying
    all_alerts.extend(
        _detect_password_spraying(
            failure_events=failure_events,
            window_minutes=spray_window_minutes,
            user_threshold=spray_user_threshold,
        )
    )

    # Règle 3 : Succès après échecs multiples
    all_alerts.extend(
        _detect_success_after_failures(
            events=deduped_events,
            lookback_minutes=compromise_window_minutes,
            fail_threshold=compromise_fail_threshold,
        )
    )

    # 4. Tri chronologique des alertes
    all_alerts.sort(
        key=lambda a: _parse_timestamp(a.timestamp) or datetime.datetime.min
    )

    # 5. Conversion en dictionnaires
    return [alert.to_dict() for alert in all_alerts]
