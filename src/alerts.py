"""Module de gestion, filtrage et export des alertes de sécurité Mini-SOC.

Ce module fait le pont entre le moteur de détection (src/detector.py)
et l'interface utilisateur Streamlit. Il propose des fonctions de normalisation,
de conversion Pandas DataFrame, de filtrage multi-critères et d'export CSV / JSON.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import pandas as pd

# Schéma standard des colonnes d'alerte pour le Mini-SOC
ALERT_COLUMNS: List[str] = [
    "timestamp",
    "rule_name",
    "severity",
    "source_ip",
    "failed_attempts",
    "target_users",
    "description",
    "mitre_technique",
]


def _normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Garantit qu'une alerte possède l'ensemble des champs requis avec des valeurs par défaut saines.

    Args:
        alert: Dictionnaire d'alerte brut ou incomplet.

    Returns:
        Dictionnaire d'alerte conforme au schéma ALERT_COLUMNS.
    """
    if not isinstance(alert, dict):
        return {col: "" if col != "failed_attempts" and col != "target_users" else (0 if col == "failed_attempts" else []) for col in ALERT_COLUMNS}

    raw_users = alert.get("target_users")
    if isinstance(raw_users, list):
        target_users = [str(u) for u in raw_users if u is not None]
    elif raw_users is not None:
        target_users = [str(raw_users)]
    else:
        target_users = []

    raw_attempts = alert.get("failed_attempts")
    try:
        failed_attempts = int(raw_attempts) if raw_attempts is not None else 0
    except (ValueError, TypeError):
        failed_attempts = 0

    return {
        "timestamp": str(alert.get("timestamp") or "").strip(),
        "rule_name": str(alert.get("rule_name") or "Unknown Rule").strip(),
        "severity": str(alert.get("severity") or "medium").strip().lower(),
        "source_ip": str(alert.get("source_ip") or "0.0.0.0").strip(),
        "failed_attempts": failed_attempts,
        "target_users": target_users,
        "description": str(alert.get("description") or "").strip(),
        "mitre_technique": str(alert.get("mitre_technique") or "T1110").strip(),
    }


def _ensure_alert_list(alerts: Union[List[Dict[str, Any]], pd.DataFrame]) -> List[Dict[str, Any]]:
    """Convertit de manière transparente un DataFrame ou une liste en liste de dictionnaires normalisés."""
    if isinstance(alerts, pd.DataFrame):
        if alerts.empty:
            return []
        raw_list = alerts.to_dict(orient="records")
    elif isinstance(alerts, list):
        raw_list = alerts
    else:
        return []

    return [_normalize_alert(a) for a in raw_list if isinstance(a, dict)]


def alerts_to_dataframe(
    alerts: Union[List[Dict[str, Any]], pd.DataFrame],
    format_users_for_display: bool = False,
) -> pd.DataFrame:
    """Convertit une liste d'alertes en DataFrame Pandas structuré pour Streamlit.

    Gère proprement les listes vides et préserve l'ordre chronologique des colonnes.

    Args:
        alerts: Liste d'alertes ou DataFrame existant.
        format_users_for_display: Si True, convertit la liste 'target_users' en chaîne
                                  séparée par des virgules pour faciliter la lecture dans un tableau UI.

    Returns:
        DataFrame Pandas typé et prêt pour st.dataframe() ou st.table().
    """
    clean_list = _ensure_alert_list(alerts)

    if not clean_list:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    df = pd.DataFrame(clean_list)

    # Réordonnancement strict des colonnes
    for col in ALERT_COLUMNS:
        if col not in df.columns:
            df[col] = None
    df = df[ALERT_COLUMNS]

    if format_users_for_display:
        df["target_users"] = df["target_users"].apply(
            lambda users: ", ".join(users) if isinstance(users, list) else str(users or "")
        )

    return df


def filter_alerts(
    alerts: Union[List[Dict[str, Any]], pd.DataFrame],
    severities: Optional[Union[str, Sequence[str]]] = None,
    source_ips: Optional[Union[str, Sequence[str]]] = None,
    rule_names: Optional[Union[str, Sequence[str]]] = None,
    mitre_techniques: Optional[Union[str, Sequence[str]]] = None,
) -> List[Dict[str, Any]]:
    """Filtre multi-critères sur un ensemble d'alertes.

    Permet de combiner plusieurs filtres (sévérité, IP, nom de règle, technique MITRE).
    Accepte des valeurs uniques ou des listes/tuples de valeurs.

    Args:
        alerts: Liste d'alertes ou DataFrame source.
        severities: Une sévérité ou liste de sévérités à conserver ('low', 'medium', 'high', 'critical').
        source_ips: Une adresse IP ou liste d'adresses IP à filtrer.
        rule_names: Un nom de règle ou liste de règles à filtrer.
        mitre_techniques: Une technique MITRE (ex: 'T1110.001') ou liste de techniques.

    Returns:
        Liste d'alertes filtrées.
    """
    clean_list = _ensure_alert_list(alerts)
    if not clean_list:
        return []

    # Normalisation des critères sous forme de sets pour recherche rapide O(1)
    def _to_set(val: Optional[Union[str, Sequence[str]]], lower: bool = False) -> Optional[set[str]]:
        if val is None:
            return None
        if isinstance(val, str):
            val = [val]
        return {str(item).lower() if lower else str(item) for item in val}

    sev_set = _to_set(severities, lower=True)
    ip_set = _to_set(source_ips, lower=False)
    rule_set = _to_set(rule_names, lower=False)
    mitre_set = _to_set(mitre_techniques, lower=False)

    filtered: List[Dict[str, Any]] = []

    for alert in clean_list:
        if sev_set is not None and alert["severity"] not in sev_set:
            continue
        if ip_set is not None and alert["source_ip"] not in ip_set:
            continue
        if rule_set is not None and alert["rule_name"] not in rule_set:
            continue
        if mitre_set is not None and alert["mitre_technique"] not in mitre_set:
            continue
        filtered.append(alert)

    return filtered


def filter_by_severity(
    alerts: Union[List[Dict[str, Any]], pd.DataFrame],
    severities: Union[str, Sequence[str]],
) -> List[Dict[str, Any]]:
    """Filtre les alertes selon une ou plusieurs sévérités données."""
    return filter_alerts(alerts, severities=severities)


def filter_by_source_ip(
    alerts: Union[List[Dict[str, Any]], pd.DataFrame],
    source_ip: Union[str, Sequence[str]],
) -> List[Dict[str, Any]]:
    """Filtre les alertes associées à une ou plusieurs adresses IP source."""
    return filter_alerts(alerts, source_ips=source_ip)


def filter_by_rule_name(
    alerts: Union[List[Dict[str, Any]], pd.DataFrame],
    rule_names: Union[str, Sequence[str]],
) -> List[Dict[str, Any]]:
    """Filtre les alertes selon le nom de la règle de détection."""
    return filter_alerts(alerts, rule_names=rule_names)


def filter_by_mitre(
    alerts: Union[List[Dict[str, Any]], pd.DataFrame],
    techniques: Union[str, Sequence[str]],
) -> List[Dict[str, Any]]:
    """Filtre les alertes selon l'identifiant de technique MITRE ATT&CK."""
    return filter_alerts(alerts, mitre_techniques=techniques)


def get_high_and_critical_alerts(
    alerts: Union[List[Dict[str, Any]], pd.DataFrame],
) -> List[Dict[str, Any]]:
    """Extrait en priorité les incidents de sévérité 'high' et 'critical'.

    Cette fonction est particulièrement utile pour alimenter les indicateurs clés (KPI)
    et les bandeaux d'alerte prioritaires dans un tableau de bord SOC.

    Args:
        alerts: Liste d'alertes ou DataFrame source.

    Returns:
        Liste contenant exclusivement les alertes de sévérité High et Critical.
    """
    return filter_alerts(alerts, severities=["high", "critical"])


def export_to_csv(
    alerts: Union[List[Dict[str, Any]], pd.DataFrame],
    file_path: Optional[Union[str, Path]] = None,
) -> str:
    """Exporte les alertes au format CSV structuré.

    Pour éviter les corruptions de format dans les tableurs, la liste 'target_users'
    est sérialisée sous forme de chaîne délimitée par des points-virgules.

    Args:
        alerts: Alertes à exporter.
        file_path: Chemin facultatif vers lequel sauvegarder le fichier CSV.

    Returns:
        Le contenu CSV sous forme de chaîne de caractères UTF-8.
    """
    clean_list = _ensure_alert_list(alerts)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=ALERT_COLUMNS, lineterminator="\n")
    writer.writeheader()

    for item in clean_list:
        row = dict(item)
        # Sérialisation propre de la liste d'utilisateurs
        if isinstance(row.get("target_users"), list):
            row["target_users"] = ";".join(row["target_users"])
        writer.writerow(row)

    csv_data = output.getvalue()

    if file_path is not None:
        target_path = Path(file_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(csv_data, encoding="utf-8")

    return csv_data


def export_to_json(
    alerts: Union[List[Dict[str, Any]], pd.DataFrame],
    file_path: Optional[Union[str, Path]] = None,
    indent: int = 2,
) -> str:
    """Exporte les alertes au format JSON formatté.

    Args:
        alerts: Alertes à exporter.
        file_path: Chemin facultatif vers lequel sauvegarder le fichier JSON.
        indent: Indentation pour la mise en forme du JSON (défaut: 2).

    Returns:
        Le contenu JSON sous forme de chaîne de caractères UTF-8.
    """
    clean_list = _ensure_alert_list(alerts)
    json_data = json.dumps(clean_list, indent=indent, ensure_ascii=False)

    if file_path is not None:
        target_path = Path(file_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json_data, encoding="utf-8")

    return json_data
