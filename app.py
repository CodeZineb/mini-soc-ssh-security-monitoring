"""Mini-SOC — Plateforme d'analyse et de triage des journaux d'authentification SSH.

Ce tableau de bord interactif Streamlit permet à un analyste SOC d'ingérer des logs
Linux auth.log, d'exécuter le moteur de détection de menaces (brute force, password spray,
compromission) et de trier les alertes selon le framework MITRE ATT&CK.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.alerts import (
    alerts_to_dataframe,
    export_to_csv,
    export_to_json,
    filter_alerts,
    get_high_and_critical_alerts,
)
from src.detector import (
    AUTH_FAILURE_TYPES,
    AUTH_SUCCESS_TYPES,
    detect_threats,
)
from src.log_parser import parse_log_file, parse_log_line

# ---------------------------------------------------------------------------
# Configuration de la page Streamlit
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Mini-SOC — SSH Security Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Fonctions de chargement et d'analyse des logs
# ---------------------------------------------------------------------------
def load_and_parse_logs(
    source_choice: str,
    uploaded_file: Optional[Any] = None,
    default_year: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    """Charge et parse les journaux selon la source sélectionnée par l'analyste.

    Args:
        source_choice: Nom du jeu prédéfini ou indicateur d'upload.
        uploaded_file: Fichier uploadé par st.file_uploader le cas échéant.
        default_year: Année par défaut pour les timestamps Syslog BSD.

    Returns:
        Un tuple contenant la liste des événements structurés et le libellé de la source.
    """
    if default_year is None:
        default_year = datetime.datetime.now().year

    # Cas 1 : Upload de fichier personnalisé
    if source_choice == "Custom Upload":
        if uploaded_file is None:
            return [], "Aucun fichier téléversé"

        try:
            content = uploaded_file.getvalue().decode("utf-8", errors="replace")
            lines = content.splitlines()
            events: List[Dict[str, Any]] = []
            for line in lines:
                ev = parse_log_line(line, default_year=default_year)
                if ev.event_type not in ("empty", "comment", "unknown"):
                    events.append(ev.to_dict())
            return events, f"Fichier téléversé : {uploaded_file.name} ({len(lines)} lignes)"
        except Exception as err:
            st.error(f"Erreur lors du traitement du fichier téléversé : {err}")
            return [], "Erreur de lecture"

    # Cas 2 : Jeux de données locaux
    path = Path(source_choice)
    if not path.is_file():
        st.warning(f"Fichier de logs introuvable sur le disque : {path}")
        return [], f"Fichier absent : {source_choice}"

    try:
        events = parse_log_file(path, include_unknown=False, default_year=default_year)
        return events, f"Jeu de données : {path.name}"
    except Exception as err:
        st.error(f"Erreur lors de la lecture du fichier {path} : {err}")
        return [], "Erreur de lecture"


# ---------------------------------------------------------------------------
# Composants d'interface (KPI, Graphiques, Alertes)
# ---------------------------------------------------------------------------
def render_header() -> None:
    """Affiche l'en-tête principal et les mentions d'avertissement éducatif."""
    st.title("🛡️ Mini-SOC — SSH Security Monitoring")
    st.subheader("Log analysis, threat detection and incident triage")
    st.info(
        "ℹ️ **Notice opérationnelle :** Educational / synthetic log analysis — passive monitoring only. "
        "Toutes les analyses sont locales et passives ; aucune connexion réseau n'est initiée.",
        icon="ℹ️",
    )


def render_kpis(events: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> None:
    """Affiche les 4 cartes métriques clés au sommet du tableau de bord."""
    col1, col2, col3, col4 = st.columns(4)

    total_events = len(events)
    unique_ips = len({e.get("source_ip") for e in events if e.get("source_ip")})
    total_alerts = len(alerts)
    high_crit_count = len(get_high_and_critical_alerts(alerts))

    with col1:
        st.metric(label="Total Events", value=f"{total_events:,}")
    with col2:
        st.metric(label="Unique Source IPs", value=unique_ips)
    with col3:
        st.metric(label="Total Alerts", value=total_alerts)
    with col4:
        st.metric(
            label="High / Critical Alerts",
            value=high_crit_count,
            delta=f"{high_crit_count} urgents" if high_crit_count > 0 else "0",
            delta_color="inverse" if high_crit_count > 0 else "normal",
        )


def render_charts(events: List[Dict[str, Any]]) -> None:
    """Génère et affiche les visualisations analytiques temporelles et volumétriques."""
    if not events:
        st.info("Aucune donnée d'événement disponible pour générer les graphiques.")
        return

    df_events = pd.DataFrame(events)

    # Filtrer les événements ayant un timestamp valide
    df_events = df_events[df_events["timestamp"].notnull()].copy()
    if df_events.empty:
        st.info("Les événements ne contiennent aucun horodatage exploitable pour les graphiques.")
        return

    df_events["dt"] = pd.to_datetime(df_events["timestamp"], errors="coerce")
    df_events = df_events.dropna(subset=["dt"]).sort_values("dt")

    # Qualification des statuts auth
    def _categorize_status(ev_type: str) -> str:
        if ev_type in AUTH_FAILURE_TYPES:
            return "Failed Authentication"
        if ev_type in AUTH_SUCCESS_TYPES:
            return "Successful Authentication"
        return "Other"

    df_events["Status"] = df_events["event_type"].apply(_categorize_status)
    auth_df = df_events[df_events["Status"].isin(["Failed Authentication", "Successful Authentication"])].copy()

    # 1. Graphique temporel : Authentication Activity Over Time
    st.markdown("### Authentication Activity Over Time")
    if not auth_df.empty:
        # Agrégation par tranches de 2 minutes pour une bonne visibilité
        auth_df["time_bucket"] = auth_df["dt"].dt.floor("2min")
        timeline = (
            auth_df.groupby(["time_bucket", "Status"])
            .size()
            .reset_index(name="Count")
        )

        fig_time = px.bar(
            timeline,
            x="time_bucket",
            y="Count",
            color="Status",
            color_discrete_map={
                "Failed Authentication": "#ef4444",      # Rouge
                "Successful Authentication": "#10b981",  # Vert
            },
            labels={"time_bucket": "Heure de l'événement", "Count": "Nombre d'événements"},
            title="Authentication Activity Over Time",
            barmode="stack",
        )
        fig_time.update_layout(
            margin=dict(l=20, r=20, t=40, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            xaxis_title="",
        )
        st.plotly_chart(fig_time, use_container_width=True)
    else:
        st.info("Aucune tentative de connexion réussie ou échouée trouvée.")

    # Colonnes pour les distributions IP et Utilisateurs
    col_left, col_right = st.columns(2)

    failures_df = df_events[df_events["event_type"].isin(AUTH_FAILURE_TYPES)].copy()

    # 2. Graphique Top Source IPs
    with col_left:
        st.markdown("### Top Source IPs")
        if not failures_df.empty and failures_df["source_ip"].notnull().any():
            top_ips = (
                failures_df["source_ip"]
                .value_counts()
                .head(10)
                .reset_index(name="Attempts")
            )
            top_ips.columns = ["Source IP", "Attempts"]

            fig_ips = px.bar(
                top_ips,
                x="Attempts",
                y="Source IP",
                orientation="h",
                color="Attempts",
                color_continuous_scale="Reds",
                title="Top Source IPs (Failed Logins)",
            )
            fig_ips.update_layout(
                yaxis=dict(autorange="reversed"),
                margin=dict(l=20, r=20, t=40, b=20),
                coloraxis_showscale=False,
            )
            st.plotly_chart(fig_ips, use_container_width=True)
        else:
            st.info("Aucun échec d'authentification enregistré par adresse IP.")

    # 3. Graphique Top Targeted Users
    with col_right:
        st.markdown("### Most Targeted Accounts")
        if not failures_df.empty and failures_df["username"].notnull().any():
            top_users = (
                failures_df["username"]
                .dropna()
                .value_counts()
                .head(10)
                .reset_index(name="Attempts")
            )
            top_users.columns = ["Username", "Attempts"]

            fig_users = px.bar(
                top_users,
                x="Attempts",
                y="Username",
                orientation="h",
                color="Attempts",
                color_continuous_scale="Oranges",
                title="Most Targeted Accounts (Failed Logins)",
            )
            fig_users.update_layout(
                yaxis=dict(autorange="reversed"),
                margin=dict(l=20, r=20, t=40, b=20),
                coloraxis_showscale=False,
            )
            st.plotly_chart(fig_users, use_container_width=True)
        else:
            st.info("Aucun utilisateur ciblé identifié dans les échecs.")


def _style_severity(val: Any) -> str:
    """Applique une coloration discrète et professionnelle sur la sévérité."""
    s = str(val).lower()
    if s == "critical":
        return "background-color: rgba(239, 68, 68, 0.25); color: #991b1b; font-weight: bold;"
    if s == "high":
        return "background-color: rgba(249, 115, 22, 0.20); color: #c2410c; font-weight: bold;"
    if s == "medium":
        return "background-color: rgba(234, 179, 8, 0.15); color: #854d0e;"
    return ""


def render_alerts_section(alerts: List[Dict[str, Any]]) -> None:
    """Affiche le tableau des alertes de sécurité et les commandes d'exportation."""
    st.markdown("### Security Alerts")

    if not alerts:
        st.success("✅ Aucune alerte de sécurité déclenchée pour les critères et le fichier sélectionnés.")
        return

    # Conversion en DataFrame formaté
    df_alerts = alerts_to_dataframe(alerts, format_users_for_display=True)

    # Renommage des colonnes pour un affichage soigné
    display_df = df_alerts.rename(
        columns={
            "timestamp": "Timestamp",
            "severity": "Severity",
            "rule_name": "Rule",
            "source_ip": "Source IP",
            "failed_attempts": "Failed Attempts",
            "target_users": "Target Users",
            "mitre_technique": "MITRE Technique",
            "description": "Description",
        }
    )

    try:
        styled_df = display_df.style.map(_style_severity, subset=["Severity"])
        st.dataframe(styled_df, use_container_width=True, height=280)
    except Exception:
        st.dataframe(display_df, use_container_width=True, height=280)

    # Boutons d'exportation CSV et JSON
    col_csv, col_json, _ = st.columns([1.5, 1.5, 5])
    with col_csv:
        csv_data = export_to_csv(alerts)
        st.download_button(
            label="📥 Download CSV",
            data=csv_data,
            file_name=f"soc_alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with col_json:
        json_data = export_to_json(alerts)
        st.download_button(
            label="📥 Download JSON",
            data=json_data,
            file_name=f"soc_alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )


def render_incident_details(alerts: List[Dict[str, Any]]) -> None:
    """Permet à l'analyste de sélectionner une alerte pour afficher ses détails et recommandations."""
    st.markdown("### Incident Details & Triage")

    if not alerts:
        st.info("Aucun incident disponible pour affichage détaillé.")
        return

    # Sélecteur d'alerte par libellé explicite
    alert_options = [
        f"#{i+1} | [{a.get('severity', '').upper()}] {a.get('timestamp', '')} — {a.get('rule_name', '')} (IP: {a.get('source_ip', '')})"
        for i, a in enumerate(alerts)
    ]

    selected_idx = st.selectbox(
        "Sélectionnez une alerte à investiguer :",
        options=range(len(alerts)),
        format_func=lambda idx: alert_options[idx],
    )

    chosen_alert = alerts[selected_idx]

    # Grille de détails de l'incident
    det_c1, det_c2, det_c3, det_c4 = st.columns(4)
    with det_c1:
        st.markdown(f"**Timestamp :** `{chosen_alert.get('timestamp')}`")
        st.markdown(f"**Severity :** `{chosen_alert.get('severity', '').upper()}`")
    with det_c2:
        st.markdown(f"**Source IP :** `{chosen_alert.get('source_ip')}`")
        st.markdown(f"**Failed Attempts :** `{chosen_alert.get('failed_attempts')}`")
    with det_c3:
        st.markdown(f"**Rule Triggered :** `{chosen_alert.get('rule_name')}`")
        st.markdown(f"**MITRE ATT&CK :** `{chosen_alert.get('mitre_technique')}`")
    with det_c4:
        users = chosen_alert.get("target_users", [])
        users_str = ", ".join(users) if isinstance(users, list) else str(users)
        st.markdown(f"**Target Accounts :** `{users_str or 'N/A'}`")

    st.markdown(f"**Description détaillée :** {chosen_alert.get('description')}")

    # Section Recommandations Analyste
    st.markdown("#### Recommended analyst action")
    st.markdown(
        """
        * **1. Corrélation des journaux système :** Vérifier les logs réseau (firewall, flux proxy), les journaux sudo et les accès PAM pour identifier les mouvements latéraux éventuels.
        * **2. Audit d'activité du compte :** Contrôler l'historique récent du compte ciblé (`last`, `lastlog`, commandes shell exécutées dans `~/.bash_history`).
        * **3. Examen des connexions réussies :** Si une session a été ouverte après une série d'échecs, inspecter les clés autorisées dans `~/.ssh/authorized_keys` et les processus enfants lancés.
        * **4. Mesures conservatoires :** Envisager une réinitialisation immédiate des identifiants et l'invalidation des sessions actives si la compromission est suspectée.
        * **5. Durcissement SSH recommandé :** Désactiver l'authentification par mot de passe au profit exclusif de clés SSH (`PasswordAuthentication no`), interdire le login root direct (`PermitRootLogin no`) et activer un mécanisme de bannissement automatisé (ex: Fail2ban).
        """
    )
    st.caption(
        "⚠️ *Avertissement SOC :* Les détections ci-dessus constituent des indicateurs comportementaux anormaux. "
        "Une analyse contextuelle approfondie est toujours nécessaire avant de conclure formellement à une compromission."
    )


# ---------------------------------------------------------------------------
# Fonction principale d'orchestration
# ---------------------------------------------------------------------------
def main() -> None:
    """Point d'entrée principal du dashboard Streamlit."""
    render_header()

    # --- SIDEBAR : Contrôles & Ingestion ---
    st.sidebar.header("📁 Source des données")
    source_type = st.sidebar.radio(
        "Sélectionnez le jeu de logs :",
        options=[
            "data/brute_force_scenario.log",
            "data/synthetic_auth.log",
            "Custom Upload",
        ],
        index=0,
        help="Choisissez un jeu de test synthétique ou déposez votre propre fichier auth.log",
    )

    uploaded_file = None
    if source_type == "Custom Upload":
        uploaded_file = st.sidebar.file_uploader(
            "Importer un fichier de logs (.log, .txt) :",
            type=["log", "txt"],
            help="Fichier auth.log au format standard Linux Syslog",
        )

    # Chargement et parsing
    events, source_label = load_and_parse_logs(
        source_choice=source_type,
        uploaded_file=uploaded_file,
    )

    st.sidebar.caption(f"**Source active :** {source_label}")

    # Paramètres de détection configurables
    st.sidebar.header("⚙️ Paramètres de Détection")
    bf_window = st.sidebar.selectbox(
        "Fenêtre Force Brute (minutes) :",
        options=[1, 5, 15],
        index=1,
    )
    bf_threshold = st.sidebar.slider(
        "Seuil d'échecs Force Brute :",
        min_value=2,
        max_value=20,
        value=5,
    )

    # Exécution du moteur de détection
    raw_alerts = detect_threats(
        events=events,
        brute_force_window_minutes=bf_window,
        brute_force_threshold=bf_threshold,
    )

    # --- SIDEBAR : Filtres des alertes ---
    st.sidebar.header("🔍 Filtres des Alertes")

    # Options disponibles déduites des alertes générées
    available_severities = ["medium", "high", "critical"]
    available_ips = sorted({a.get("source_ip", "") for a in raw_alerts if a.get("source_ip")})
    available_rules = sorted({a.get("rule_name", "") for a in raw_alerts if a.get("rule_name")})
    available_mitre = sorted({a.get("mitre_technique", "") for a in raw_alerts if a.get("mitre_technique")})

    sel_severities = st.sidebar.multiselect(
        "Sévérité :",
        options=available_severities,
        default=available_severities,
    )

    sel_ips = st.sidebar.multiselect(
        "Adresses IP source :",
        options=available_ips,
        default=available_ips,
    )

    sel_rules = st.sidebar.multiselect(
        "Règles déclenchées :",
        options=available_rules,
        default=available_rules,
    )

    sel_mitre = st.sidebar.multiselect(
        "Techniques MITRE :",
        options=available_mitre,
        default=available_mitre,
    )

    # Application des filtres via src/alerts.py
    filtered_alerts = filter_alerts(
        alerts=raw_alerts,
        severities=sel_severities if sel_severities else None,
        source_ips=sel_ips if sel_ips else None,
        rule_names=sel_rules if sel_rules else None,
        mitre_techniques=sel_mitre if sel_mitre else None,
    )

    # --- Corps du Dashboard ---
    render_kpis(events=events, alerts=filtered_alerts)
    st.divider()

    render_charts(events=events)
    st.divider()

    render_alerts_section(alerts=filtered_alerts)
    st.divider()

    render_incident_details(alerts=filtered_alerts)


if __name__ == "__main__":
    main()
