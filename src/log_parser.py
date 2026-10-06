"""Module de parsing des logs d'authentification Linux (auth.log / syslog).

Ce module transforme des flux de lignes de logs bruts en événements structurés
exploitables par le moteur de détection SIEM/SOC. Il utilise exclusivement
la bibliothèque standard Python et résiste aux lignes inconnues ou malformées.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# ---------------------------------------------------------------------------
# Motifs d'en-tête Syslog
# ---------------------------------------------------------------------------

# Format Syslog BSD classique : "Oct 14 09:40:02 soc-node-01 sshd[40201]: ..."
SYSLOG_BSD_HEADER = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<hostname>[\w\.\-]+)"
    r"\s+(?P<process>[\w\.\-\(\):/]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

# Format ISO 8601 (RFC 5424) : "2026-10-14T09:40:02.123456+00:00 soc-node-01 sshd[40201]: ..."
SYSLOG_ISO_HEADER = re.compile(
    r"^(?P<iso_time>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<hostname>[\w\.\-]+)"
    r"\s+(?P<process>[\w\.\-\(\):/]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

# Mois abrégés en index numérique pour normalisation
MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# ---------------------------------------------------------------------------
# Motifs de détection des événements SSH & PAM
# ---------------------------------------------------------------------------

EVENT_PATTERNS = [
    # 1. Failed password (avec ou sans mention invalid user)
    (
        "failed_password",
        re.compile(
            r"^Failed password for (?P<invalid>invalid user )?(?P<username>\S+) "
            r"from (?P<source_ip>[\d\.]+|[a-fA-F0-9:]+) port (?P<source_port>\d+) ssh2"
        ),
    ),
    # 2. Accepted password
    (
        "accepted_password",
        re.compile(
            r"^Accepted password for (?P<username>\S+) "
            r"from (?P<source_ip>[\d\.]+|[a-fA-F0-9:]+) port (?P<source_port>\d+) ssh2"
        ),
    ),
    # 3. Accepted publickey
    (
        "accepted_publickey",
        re.compile(
            r"^Accepted publickey for (?P<username>\S+) "
            r"from (?P<source_ip>[\d\.]+|[a-fA-F0-9:]+) port (?P<source_port>\d+) ssh2"
        ),
    ),
    # 4. Invalid user attempt
    (
        "invalid_user",
        re.compile(
            r"^Invalid user (?P<username>\S+) "
            r"from (?P<source_ip>[\d\.]+|[a-fA-F0-9:]+)(?: port (?P<source_port>\d+))?"
        ),
    ),
    # 5. Failed publickey
    (
        "failed_publickey",
        re.compile(
            r"^Failed publickey for (?P<invalid>invalid user )?(?P<username>\S+) "
            r"from (?P<source_ip>[\d\.]+|[a-fA-F0-9:]+) port (?P<source_port>\d+) ssh2"
        ),
    ),
    # 6. Failed keyboard-interactive / pam
    (
        "failed_keyboard_interactive",
        re.compile(
            r"^Failed keyboard-interactive(?:/pam)? for (?P<invalid>invalid user )?(?P<username>\S+) "
            r"from (?P<source_ip>[\d\.]+|[a-fA-F0-9:]+) port (?P<source_port>\d+) ssh2"
        ),
    ),
    # 7. Disconnect / Session closed
    (
        "session_closed",
        re.compile(
            r"^pam_unix\([\w:\.\-]+\): session closed for user (?P<username>\S+)"
        ),
    ),
    (
        "session_opened",
        re.compile(
            r"^pam_unix\([\w:\.\-]+\): session opened for user (?P<username>\S+)"
        ),
    ),
    (
        "connection_closed",
        re.compile(
            r"^Connection closed by (?:(?P<invalid>invalid user )?(?P<username>\S+) )?"
            r"(?P<source_ip>[\d\.]+|[a-fA-F0-9:]+) port (?P<source_port>\d+)"
        ),
    ),
    (
        "disconnected",
        re.compile(
            r"^(?:Received disconnect|Disconnected) from (?:(?:user )?(?P<username>\S+) )?"
            r"(?P<source_ip>[\d\.]+|[a-fA-F0-9:]+) port (?P<source_port>\d+)"
        ),
    ),
]


@dataclass
class LogEvent:
    """Représente un événement de journalisation normalisé et structuré."""

    timestamp: Optional[str]
    hostname: Optional[str]
    process: Optional[str]
    pid: Optional[int]
    event_type: str
    username: Optional[str]
    source_ip: Optional[str]
    source_port: Optional[int]
    is_invalid_user: bool
    raw_line: str

    def to_dict(self) -> Dict[str, Any]:
        """Convertit l'événement en dictionnaire natif pour faciliter l'export ou l'intégration Pandas."""
        return asdict(self)


def _normalize_timestamp(
    header_match: re.Match[str],
    is_iso: bool,
    default_year: Optional[int] = None,
) -> Optional[str]:
    """Normalise la date du log au format standard 'YYYY-MM-DD HH:MM:SS'.

    Si l'année n'est pas précisée (syslog BSD classique), utilise default_year
    ou l'année en cours.
    """
    if is_iso:
        raw_iso = header_match.group("iso_time")
        # Remplacement de 'T' par un espace et tronquage des microsecondes/fuseau
        cleaned = raw_iso.replace("T", " ")
        if "+" in cleaned:
            cleaned = cleaned.split("+")[0]
        elif "-" in cleaned[10:]:
            # Gestion d'un éventuel fuseau négatif "-05:00"
            prefix, tz = cleaned[:10], cleaned[10:]
            if "-" in tz:
                cleaned = prefix + tz.split("-")[0]
        if "Z" in cleaned:
            cleaned = cleaned.replace("Z", "")
        return cleaned.strip()

    month_name = header_match.group("month")
    month_num = MONTH_MAP.get(month_name, 1)
    day = int(header_match.group("day"))
    time_str = header_match.group("time")

    year = default_year if default_year is not None else datetime.datetime.now().year
    return f"{year:04d}-{month_num:02d}-{day:02d} {time_str}"


def parse_log_line(
    line: str,
    default_year: Optional[int] = None,
) -> LogEvent:
    """Parse une unique ligne de log Linux auth.log / syslog en événement structuré.

    Cette fonction est garantie sans levée d'exception : si la ligne est inconnue,
    vide ou malformée, elle retourne un LogEvent avec event_type='unknown'.

    Args:
        line: La chaîne brute représentant la ligne de log.
        default_year: L'année à affecter aux timestamps Syslog BSD qui omettent l'année.

    Returns:
        LogEvent contenant tous les champs extraits ou avec les valeurs par défaut.
    """
    cleaned_line = line.strip()

    # Ignorer les lignes vides ou les commentaires
    if not cleaned_line or cleaned_line.startswith("#"):
        return LogEvent(
            timestamp=None,
            hostname=None,
            process=None,
            pid=None,
            event_type="comment" if cleaned_line.startswith("#") else "empty",
            username=None,
            source_ip=None,
            source_port=None,
            is_invalid_user=False,
            raw_line=line,
        )

    # 1. Extraction de l'en-tête Syslog
    header_match = SYSLOG_BSD_HEADER.match(cleaned_line)
    is_iso = False

    if not header_match:
        header_match = SYSLOG_ISO_HEADER.match(cleaned_line)
        is_iso = True

    if not header_match:
        # Ligne de log non conforme à Syslog standard
        return LogEvent(
            timestamp=None,
            hostname=None,
            process=None,
            pid=None,
            event_type="unknown",
            username=None,
            source_ip=None,
            source_port=None,
            is_invalid_user=False,
            raw_line=line,
        )

    # Métadonnées d'en-tête
    timestamp = _normalize_timestamp(header_match, is_iso=is_iso, default_year=default_year)
    hostname = header_match.group("hostname")
    process = header_match.group("process")
    raw_pid = header_match.group("pid")
    pid = int(raw_pid) if raw_pid and raw_pid.isdigit() else None
    message = header_match.group("message")

    # 2. Identification du type d'événement et extraction du message applicatif
    event_type = "unknown"
    username: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    is_invalid_user = False

    for candidate_type, pattern in EVENT_PATTERNS:
        match = pattern.search(message)
        if match:
            event_type = candidate_type
            groups = match.groupdict()

            username = groups.get("username")
            source_ip = groups.get("source_ip")
            port_val = groups.get("source_port")
            source_port = int(port_val) if port_val and port_val.isdigit() else None

            if groups.get("invalid"):
                is_invalid_user = True
            elif candidate_type == "invalid_user":
                is_invalid_user = True

            break

    return LogEvent(
        timestamp=timestamp,
        hostname=hostname,
        process=process,
        pid=pid,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        source_port=source_port,
        is_invalid_user=is_invalid_user,
        raw_line=line,
    )


def parse_log_file(
    path: Union[str, Path],
    include_unknown: bool = False,
    default_year: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Lit et parse un fichier de logs complet en une liste d'événements structurés (dictionnaires).

    Args:
        path: Chemin absolu ou relatif vers le fichier de logs.
        include_unknown: Si False, filtre les commentaires, lignes vides et événements non reconnus.
                         Si True, conserve tous les enregistrements.
        default_year: Année par défaut pour les timestamps sans mention d'année.

    Returns:
        Une liste de dictionnaires prêts à être consommés par Pandas ou le moteur de corrélation.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Le fichier de logs spécifié est introuvable : {file_path}")

    parsed_events: List[Dict[str, Any]] = []

    with file_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            event = parse_log_line(line, default_year=default_year)

            if not include_unknown and event.event_type in ("empty", "comment", "unknown"):
                continue

            parsed_events.append(event.to_dict())

    return parsed_events
