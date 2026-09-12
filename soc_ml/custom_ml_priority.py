#!/usr/bin/env python3
"""
custom-ml-priority.py

Wazuh ML Alert Prioritization Integration Script

Purpose:
- Wazuh Integrator passes one alert JSON file to this script.
- The script extracts the same 21 features used during model training.
- It loads the trained Random Forest model and threshold.
- It produces ML priority and final priority.
- A narrow safety validation layer escalates deterministic high-risk indicators.
- Results are written to /var/ossec/logs/ml_priority.log.
"""

import sys
import os
import json
import re
import logging
from urllib.parse import unquote_plus

# Paths
MODEL_DIR = "/var/ossec/ml_models"
LOG_FILE = "/var/ossec/logs/ml_priority.log"

MODEL_PATH = os.path.join(MODEL_DIR, "alert_priority_model_tuned.pkl")
THRESHOLD_PATH = os.path.join(MODEL_DIR, "model_threshold.pkl")
FEATURES_PATH = os.path.join(MODEL_DIR, "feature_columns.pkl")

# Logging setup
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


def log_info(message: str):
    logging.info(message)


def log_error(message: str):
    logging.error(message)


# Load ML dependencies and model files
try:
    import joblib
    import pandas as pd

    model = joblib.load(MODEL_PATH)
    threshold = joblib.load(THRESHOLD_PATH)
    features = joblib.load(FEATURES_PATH)

    log_info(
        f"MODEL_LOADED | threshold={threshold} | feature_count={len(features)}"
    )

except Exception as e:
    log_error(f"FATAL_MODEL_LOAD_ERROR | error={e}")
    sys.exit(1)


def safe_int(value, default=0):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def extract_web_context(alert: dict) -> dict:
    """Collect request and User-Agent data from common Wazuh fields."""

    if "_source" in alert:
        alert = alert["_source"]

    data = alert.get("data", {}) or {}
    http_data = data.get("http", {}) or {}
    if not isinstance(http_data, dict):
        http_data = {}

    request_fields = [
        data.get("url", ""),
        data.get("uri", ""),
        data.get("request", ""),
        data.get("query", ""),
        data.get("query_string", ""),
        data.get("request_uri", ""),
        http_data.get("url", ""),
        http_data.get("uri", ""),
        http_data.get("request", ""),
        alert.get("full_log", ""),
    ]

    user_agent_fields = [
        data.get("user_agent", ""),
        data.get("http_user_agent", ""),
        data.get("ua", ""),
        http_data.get("user_agent", ""),
    ]

    request_text = " ".join(
        str(value) for value in request_fields if value not in (None, "")
    ).lower()

    user_agent_text = " ".join(
        str(value) for value in user_agent_fields if value not in (None, "")
    ).lower()

    try:
        request_text = unquote_plus(request_text)
    except Exception:
        pass

    return {
        "request_text": request_text,
        "user_agent_text": user_agent_text,
    }


def extract_srcip(alert: dict) -> str:
    """
    Extract source IP from common Wazuh, Suricata, Nginx, SSH, and full_log fields.
    Returns 'unknown' if no source IP is found.
    """

    if "_source" in alert:
        alert = alert["_source"]

    data = alert.get("data", {}) or {}
    full_log = alert.get("full_log", "") or ""

    possible_ips = [
        data.get("srcip"),
        data.get("src_ip"),
        data.get("source_ip"),
        data.get("clientip"),
        data.get("client_ip"),
        data.get("remote_addr"),
        data.get("id.orig_h"),
    ]
    # Suricata sometimes stores source IP inside nested fields
    suricata = data.get("suricata", {}) or {}
    possible_ips.extend([
         suricata.get("src_ip"),
         suricata.get("srcip"),
    ])

    # Some alerts store source IP inside the raw log text
    if full_log:
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", full_log)

        # Avoid choosing the backend/server IP first when possible
        for ip in ip_matches:
            if not ip.startswith("127."):
                possible_ips.append(ip)

    for ip in possible_ips:
        if ip and isinstance(ip, str):
            return ip.strip()

    return "unknown"



def extract_features(alert: dict) -> dict:
    """
    Convert one Wazuh alert JSON into the 21 ML features expected by the model.
    """

    # Some exports wrap alerts inside _source. Wazuh integrator usually does not,
    # but this makes the script safe for manual testing too.
    if "_source" in alert:
        alert = alert["_source"]

    rule = alert.get("rule", {})
    data = alert.get("data", {})
    agent = alert.get("agent", {})
    syscheck = alert.get("syscheck", {})

    groups = rule.get("groups", [])
    if not isinstance(groups, list):
        groups = []

    loc = alert.get("location", "").lower()
    agent_name = agent.get("name", "").lower()
    desc_lower = rule.get("description", "").lower()

    web_context = extract_web_context(alert)
    request_text = web_context["request_text"]
    user_agent_text = web_context["user_agent_text"]

    # Compatibility alias so existing traversal/recon logic continues to work.
    url = request_text

    # Features 1–2: Core Wazuh rule fields
    wazuh_rule_level = safe_int(rule.get("level", 0))
    rule_firedtimes = safe_int(rule.get("firedtimes", 1), default=1)

    # Policy noise guard
    is_policy_noise = (
        wazuh_rule_level < 5
        and "policy" in desc_lower
    )

    # Feature 3: suricata_alert_flag
    suricata_alert_flag = 1 if (
        "suricata" in groups
        or "ids" in groups
        or "suricata" in loc
    ) else 0

    # Feature 4: suricata_severity
    suricata_severity = 0
    if suricata_alert_flag:
        raw_sev = data.get("alert", {}).get("severity", "")
        if raw_sev != "":
            try:
                suricata_severity = 5 - int(raw_sev)
            except ValueError:
                suricata_severity = 2

    # Feature 5: vt_positives_ratio
    vt_positives_ratio = 0.0
    vt_data = data.get("virustotal", {})
    if vt_data:
        try:
            malicious = safe_int(
                vt_data.get("positives", vt_data.get("malicious", 0))
            )
            total_str = vt_data.get("total", "")

            if total_str == "":
                match = re.search(
                    r"(\d+) engines detected",
                    rule.get("description", "")
                )
                total = int(match.group(1)) + 4 if match else 70
            else:
                total = safe_int(total_str, default=70)

            vt_positives_ratio = round(
                malicious / total, 4
            ) if total > 0 else 0.0

        except Exception:
            vt_positives_ratio = 0.0

    # Feature 6: fim_change_flag
    fim_change_flag = 1 if (
        bool(syscheck)
        or "syscheck" in loc
        or "syscheck" in groups
        or "integrity" in desc_lower
    ) else 0

    # Feature 7: interaction_level
    interaction_level = 0

    high_interaction_groups = ["syscheck", "rootcheck"]
    medium_interaction_groups = [
        "authentication_failed",
        "attack",
        "sqlinjection",
        "invalid_login",
        "ids",
        "suricata"
    ]

    if any(g in groups for g in high_interaction_groups) or "syscheck" in loc:
        interaction_level = 2
    elif any(g in groups for g in medium_interaction_groups):
        interaction_level = 1

    if syscheck and "/root" in syscheck.get("path", ""):
        interaction_level = 2

    if vt_data and safe_int(vt_data.get("positives", vt_data.get("malicious", 0))) > 0:
        interaction_level = 2

    if is_policy_noise:
        interaction_level = 0

    # Feature 8: is_suspicious_activity
    suspicious_groups = [
        "attack",
        "sqlinjection",
        "authentication_failed",
        "invalid_login",
        "sqlmap"
    ]

    is_suspicious_activity = 1 if any(
        g in groups for g in suspicious_groups
    ) else 0

    if wazuh_rule_level >= 10:
        is_suspicious_activity = 1

    if is_policy_noise:
        is_suspicious_activity = 0

    # Feature 9: has_payload_pattern
    # SQLmap identity alone is not exploit-payload evidence.
    payload_patterns = [
        r"\bunion(?:\s+all)?\s+select\b",
        r"\bselect\b.+\bfrom\b",
        r"['\"]?\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"['\"]?\s*and\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"\bsleep\s*\(",
        r"\bbenchmark\s*\(",
        r"\bwaitfor\s+delay\b",
        r"\binformation_schema\b",
        r"\bxp_cmdshell\b",
        r"\bload_file\s*\(",
        r"\binto\s+outfile\b",
        r"\bdrop\s+table\b",
        r"\.\./",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/\.env",
        r"/\.git",
        r"<script",
        r"cmd=",
        r"exec\s*\(",
        r"eval\s*\(",
    ]

    has_payload_pattern = int(
        any(
            re.search(pattern, request_text, flags=re.IGNORECASE)
            for pattern in payload_patterns
        )
    )

    if any(
        keyword in desc_lower
        for keyword in [
            "sql injection",
            # "sqlmap",  # excluded: tool identity is not payload evidence
            "traversal",
            "shellshock",
        ]
    ):
        has_payload_pattern = 1

    # Feature 10: user_agent_suspicious_flag
    ua_keywords = [
        "sqlmap",
        "nikto",
        "nessus",
        "masscan",
        "zgrab",
        "dirbuster",
        "gobuster",
        "burpsuite",
        "nmap scripting"
    ]

    user_agent_suspicious_flag = 0

    if any(kw in desc_lower for kw in ua_keywords):
        user_agent_suspicious_flag = 1

    ua_field = user_agent_text
    if any(kw in ua_field for kw in ua_keywords):
        user_agent_suspicious_flag = 1

    if "sqlmap" in groups:
        user_agent_suspicious_flag = 1

    # Feature 11: post_access_activity_flag
    post_access_activity_flag = 0

    if syscheck and "/root" in syscheck.get("path", ""):
        post_access_activity_flag = 1

    if vt_data and safe_int(vt_data.get("positives", vt_data.get("malicious", 0))) > 0:
        post_access_activity_flag = 1

    if "rootcheck" in groups:
        post_access_activity_flag = 1

    if any(
        kw in desc_lower
        for kw in ["malware", "rootkit", "backdoor", "webshell"]
    ):
        post_access_activity_flag = 1

    
    # Feature 12: multiple_auth_failures_flag

    auth_failure_groups = ["authentication_failed", "invalid_login"]

    rule_id_for_features = str(rule.get("id", ""))

    generic_ssh_rule_ids = {
        "2501",
        "5503",
        "5710",
        "5760"
    }

    brute_force_summary_rule_ids = {
        "2502",
        "100100"
    }

    multiple_auth_failures_flag = 1 if (
        any(g in groups for g in auth_failure_groups)
        and rule_firedtimes > 1
    ) else 0

    # Generic PAM/sshd alerts represent individual authentication records.
    # Do not let repeated technical records imitate a confirmed brute-force summary.
    if rule_id_for_features in generic_ssh_rule_ids:
        rule_firedtimes = 1
        multiple_auth_failures_flag = 0
        is_suspicious_activity = 0

    # These rules explicitly confirm repeated authentication failures.
    elif rule_id_for_features in brute_force_summary_rule_ids:
       multiple_auth_failures_flag = 1
       is_suspicious_activity = 1

    # Feature 13: is_recon_activity
    recon_groups = ["sqlinjection", "attack"]

    recon_description_keywords = [
        "sql injection",
        "scan",
        "nmap",
        "port scan",
        "recon",
        "directory traversal",
        "path traversal",
        "brute force",
        "probe",
        "enumeration",
        "fuzzing",
        "web crawler"
    ]

    recon_url_keywords = [
        "/etc/passwd",
        "/etc/shadow",
        "/../",
        "/.git",
        "/.env",
        "/admin",
        "/wp-admin",
        "/phpinfo"
    ]

    is_recon_activity = 0

    if any(g in groups for g in recon_groups):
        is_recon_activity = 1

    if any(kw in desc_lower for kw in recon_description_keywords):
        is_recon_activity = 1

    if any(kw in url for kw in recon_url_keywords):
        is_recon_activity = 1

    # Feature 14: audit_alert_flag
    audit_alert_flag = 1 if (
        "audit" in groups
        or "audit" in loc
        or any(g.startswith("audit") for g in groups)
    ) else 0

    # Feature 15: http_status
    http_status = 0

    for field in ["id", "code", "status", "http_response_code"]:
        val = data.get(field, "")
        candidate = safe_int(val, default=0)

        if 100 <= candidate <= 599:
            http_status = candidate
            break

    if http_status == 0:
        match = re.search(r"\b([1-5]\d{2})\b", desc_lower)
        if match:
            http_status = safe_int(match.group(1))

    # Feature 16: is_external_ip
    is_external_ip = 0

    src_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or data.get("source_ip")
        or ""
    )

    if src_ip:
        private_ip = (
            src_ip.startswith("10.")
            or src_ip.startswith("192.168.")
            or any(src_ip.startswith(f"172.{i}.") for i in range(16, 32))
        )
        is_external_ip = 0 if private_ip else 1

    # Feature 17: multi_sensor_flag
    detection_domains = {
        "web": ["web", "accesslog"],
        "host": ["syslog", "sshd", "audit", "syscheck"],
        "network": ["ids", "suricata"],
        "threat_intel": ["virustotal"]
    }

    domains_hit = sum(
        1
        for domain_groups in detection_domains.values()
        if any(g in groups for g in domain_groups)
    )

    multi_sensor_flag = 1 if domains_hit >= 2 else 0

    # Features 18–21: service_type one-hot
    service_type_database = 1 if (
        "mysql" in loc
        or "database" in loc
    ) else 0

    service_type_honeypot = 1 if (
        "cowrie" in agent_name
        or "honeypot" in agent_name
    ) else 0

    service_type_host = 1 if (
        "audit" in loc
        or "syscheck" in loc
        or "journald" in loc
        or any(g in groups for g in ["audit", "syslog", "sshd", "local"])
    ) else 0

    service_type_web = 1 if (
        "nginx" in loc
        or "access.log" in loc
        or any(g in groups for g in ["web", "accesslog"])
    ) else 0

    if service_type_honeypot:
        service_type_web = 0
        service_type_host = 0
        service_type_database = 0
    elif service_type_database:
        service_type_web = 0
        service_type_host = 0

    return {
        "wazuh_rule_level": wazuh_rule_level,
        "rule_firedtimes": rule_firedtimes,
        "suricata_alert_flag": suricata_alert_flag,
        "suricata_severity": suricata_severity,
        "vt_positives_ratio": vt_positives_ratio,
        "fim_change_flag": fim_change_flag,
        "interaction_level": interaction_level,
        "is_suspicious_activity": is_suspicious_activity,
        "has_payload_pattern": has_payload_pattern,
        "user_agent_suspicious_flag": user_agent_suspicious_flag,
        "post_access_activity_flag": post_access_activity_flag,
        "multiple_auth_failures_flag": multiple_auth_failures_flag,
        "is_recon_activity": is_recon_activity,
        "audit_alert_flag": audit_alert_flag,
        "http_status": http_status,
        "is_external_ip": is_external_ip,
        "multi_sensor_flag": multi_sensor_flag,
        "service_type_database": service_type_database,
        "service_type_honeypot": service_type_honeypot,
        "service_type_host": service_type_host,
        "service_type_web": service_type_web,
    }

def should_auto_block(alert: dict, final_priority: str, srcip: str) -> bool:
    """
    Decide whether a HIGH final-priority alert should become an auto-block candidate.
    This is stricter than normal HIGH priority.
    """

    if "_source" in alert:
        alert = alert["_source"]

    rule = alert.get("rule", {})
    data = alert.get("data", {})

    desc = rule.get("description", "").lower()
    groups = rule.get("groups", [])
    if not isinstance(groups, list):
        groups = []
    groups_text = " ".join(groups).lower()

    web_context = extract_web_context(alert)
    url = web_context["request_text"]
    rule_id = str(rule.get("id", ""))

    if not srcip or srcip.lower() in {"unknown", "none", "null", "-"}:
        return False

    protected_ips = {
        "127.0.0.1",
        "192.168.211.136",  # Wazuh server
        "192.168.211.137",  # backend server
        "192.168.211.138",  # Cowrie/honeypot
    }

    if srcip in protected_ips:
        return False

    if str(final_priority).upper() != "HIGH":
        return False

    auto_block_keywords = [
        # "sqlmap",  # disabled: tool identity alone must not auto-block
        "sql injection",
        "sqli",
        "union select",
        "or 1=1",
        "1=1",
        "/etc/passwd",
        "../",
        "directory traversal",
        "path traversal",
    ]

    if any(k in desc or k in url or k in groups_text for k in auto_block_keywords):
        return True

    auto_block_rule_ids = {
        "31164",
        "31103",
        "31101",
        "100302",
    }

    if rule_id in auto_block_rule_ids:
        return True

    return False


def map_mitre(rule_id, description, request_text=""):
    """
    Maps selected alert types to MITRE ATT&CK tactics and techniques.
    Used only as analyst context after ML prioritization.
    """

    rid = str(rule_id)
    desc = str(description).lower()
    evidence_text = f"{description} {request_text}".lower()

    # Ordinary HTTP 400 errors and repeated 400-error summaries
    # are not automatically MITRE attack techniques.
    if rid in {"31101", "31151"}:

        sql_injection_evidence = any(
            indicator in evidence_text
            for indicator in {
                "union select",
                "sql injection",
                "information_schema",
                "sleep(",
                "benchmark(",
                " or 1=1",
                "or '1'='1",
                'or "1"="1',
                "%27%20or%20%271%27=%271",
                "%20union%20select"
            }
        )

        traversal_evidence = any(
            indicator in evidence_text
            for indicator in {
                "../",
                "..%2f",
                "%2e%2e%2f",
                "/etc/passwd",
                "/etc/shadow",
                "directory traversal",
                "path traversal",
                "sensitive file"
            }
        )

        # SQL-injection payload found in the request.
        if sql_injection_evidence:
            return {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application"
            }

        # Directory traversal or sensitive-file probing found.
        if traversal_evidence:
            return {
                "tactic": "Discovery",
                "technique_id": "T1083",
                "technique": "File and Directory Discovery"
            }

        # A repeated 400-error summary may represent probing even
        # when no confirmed exploit payload is present.
        if rid == "31151":
            return {
                "tactic": "Reconnaissance",
                "technique_id": "T1595",
                "technique": "Active Scanning"
            }

        # A single ordinary 400 error has no confirmed attack technique.
        return {
            "tactic": "Not Applicable",
            "technique_id": "Not Applicable",
            "technique": "Informational Web Error"
        }

    # Generic web-attack detections
    if rid in {"31104", "31106"}:
        return {
            "tactic": "Initial Access",
            "technique_id": "T1190",
            "technique": "Exploit Public-Facing Application"
        }

    # SQL injection / sqlmap / web exploitation
    if rid in {"31164", "31103", "100212", "100302"} or "sql injection" in desc or "sqlmap" in desc:
        return {
            "tactic": "Initial Access",
            "technique_id": "T1190",
            "technique": "Exploit Public-Facing Application"
        }

    # Directory traversal / sensitive file probing
    if rid in {"31101", "100301"} or "/etc/passwd" in desc or "path traversal" in desc or "directory traversal" in desc:
        return {
            "tactic": "Discovery",
            "technique_id": "T1083",
            "technique": "File and Directory Discovery"
        }

    # SSH brute force / repeated authentication failure
    if rid in {"2502", "100100"} or "brute" in desc or "missed the password" in desc or "unsuccessful login" in desc:
        return {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique": "Brute Force"
        }

    # Repeated invalid user / authentication failure
    if rid in {"5710", "5503", "5760", "2501"} and (
        "authentication failed" in desc
        or "user login failed" in desc
        or "non-existent user" in desc
    ):
        return {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique": "Brute Force"
        }

    # Nmap / scan / recon
    if "nmap" in desc or "scan" in desc or "port scan" in desc or "network scan" in desc:
        return {
            "tactic": "Discovery",
            "technique_id": "T1046",
            "technique": "Network Service Discovery"
        }

    # FIM / suspicious file changes
    if "file added" in desc or "file modified" in desc or "fim" in desc:
        return {
            "tactic": "Defense Evasion",
            "technique_id": "T1070",
            "technique": "Indicator Removal or File Modification"
        }

    return {
        "tactic": "N/A",
        "technique_id": "N/A",
        "technique": "N/A"
    }


def main():
    """
    Wazuh Integrator passes the temporary alert JSON path as sys.argv[1].
    """

    if len(sys.argv) < 2:
        log_error("NO_ALERT_FILE_PATH | Wazuh did not pass an alert file path")
        sys.exit(1)

    alert_file = sys.argv[1]

    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as e:
        log_error(f"ALERT_READ_ERROR | file={alert_file} | error={e}")
        sys.exit(1)

    if "_source" in alert:
        alert = alert["_source"]

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    # ------------------------------------------------------------
    # Recursion guard:
    # Do NOT process alerts created by this ML pipeline itself.
    # ------------------------------------------------------------
    rule_id_check = str(rule.get("id", ""))

    groups_check = rule.get("groups", [])
    if not isinstance(groups_check, list):
        groups_check = []

    desc_check = rule.get("description", "").lower()

    if (
        rule_id_check in {"110000", "110001", "110002", "110003", "110010"}
        or "ml_priority" in groups_check
        or "ml prioritization" in desc_check
        or "ml auto response candidate" in desc_check
    ):
        sys.exit(0)

    # Ignore routine local Wazuh manager/admin events
    agent_name_check = agent.get("name", "").lower()
    local_noise_rule_ids = {"5402", "5501", "5502"}

    if (
        agent_name_check == "wazuh-server"
        and rule_id_check in local_noise_rule_ids
        and extract_srcip(alert) == "unknown"
    ):
        sys.exit(0)

    # ------------------------------------------------------------
    # Cowrie vulnerability/package inventory noise filter:
    # Keep these findings in original Wazuh vulnerability views,
    # but do not score them as live attacker activity in the ML feed.
    # ------------------------------------------------------------
    original_desc_check = rule.get("description", "").lower()
    original_url_check = str(alert.get("data", {}).get("url", "")).lower()

    cowrie_asset = (
        "cowrie" in agent_name_check
        or "honeypot" in agent_name_check
    )

    cowrie_cve_finding = (
        cowrie_asset
        and (
            "cve-" in original_desc_check
            or "cve-" in original_url_check
            or rule_id_check in {"23584", "23585"}
        )
    )

    if cowrie_cve_finding:
        sys.exit(0)

    if cowrie_cve_finding:
        sys.exit(0)

    # Cowrie package-management events generated during setup/startup
    cowrie_dpkg_noise = (
        cowrie_asset
        and (
            rule_id_check in {"2902", "2903", "2904"}
            or "dpkg (debian package)" in original_desc_check
            or "new dpkg" in original_desc_check
        )
    )

    if cowrie_dpkg_noise:
        sys.exit(0)

    rule_id = rule.get("id", "?")
    rule_level = rule.get("level", "?")
    description = rule.get("description", "Unknown")
    agent_name = agent.get("name", "unknown")
    srcip = extract_srcip(alert)

    rule_id = rule.get("id", "?")
    rule_level = rule.get("level", "?")
    description = rule.get("description", "Unknown")
    agent_name = agent.get("name", "unknown")
    srcip = extract_srcip(alert)

    try:
        feature_dict = extract_features(alert)

        row = {
            col: feature_dict.get(col, 0)
            for col in features
        }

        X = pd.DataFrame([row])[features]

        probability = model.predict_proba(X)[0, 1]
        ml_prediction = 1 if probability >= threshold else 0
        ml_priority = "HIGH" if ml_prediction == 1 else "LOW"

        # Build request evidence for MITRE mapping.
        # Different Wazuh/Suricata alerts may store the request in different fields.
        alert_data = alert.get("data", {}) or {}
        http_data = alert_data.get("http", {}) or {}

        request_parts = [
            alert.get("full_log", ""),
            alert_data.get("url", ""),
            alert_data.get("uri", ""),
            alert_data.get("request", ""),
            alert_data.get("query", ""),
            alert_data.get("full_log", ""),
            http_data.get("url", ""),
            http_data.get("uri", ""),
            http_data.get("request", ""),
        ]

        request_text = " ".join(
            str(value)
            for value in request_parts
            if value not in (None, "")
        )

        # MITRE mapping
        mitre = map_mitre(rule_id, description, request_text)
 
        mitre_tactic = mitre["tactic"]
        mitre_id = mitre["technique_id"]
        mitre_technique = mitre["technique"]        
  
        log_info(
            f"FINAL_PRIORITY={final_priority} | "
            f"ML_PRIORITY={ml_priority} | "
            f"CONFIDENCE={probability:.3f} | "
            f"SAFETY_ACTION={safety_action} | "
            f"RULE_ID={rule_id} | "
            f"LEVEL={rule_level} | "
            f"AGENT={agent_name} | "
            f"SRCIP={srcip} | "
            f"MITRE_TACTIC={mitre_tactic} | "
            f"MITRE_ID={mitre_id} | "
            f"MITRE_TECHNIQUE={mitre_technique} | "
            f"DESC={description}"
        )

        print(
            f"FINAL_PRIORITY={final_priority} | "
            f"ML_PRIORITY={ml_priority} | "
            f"CONFIDENCE={probability:.3f} | "
            f"SAFETY_ACTION={safety_action} | "
            f"RULE_ID={rule_id} | "
            f"SRCIP={srcip} | "
            f"MITRE_TACTIC={mitre_tactic} | "
            f"MITRE_ID={mitre_id} | "
            f"MITRE_TECHNIQUE={mitre_technique}"
        )

    except Exception as e:
        log_error(
            f"ML_PRIORITY_ERROR | RULE_ID={rule_id} | "
            f"LEVEL={rule_level} | error={e}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
