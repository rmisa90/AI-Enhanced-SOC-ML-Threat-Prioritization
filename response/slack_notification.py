#!/usr/bin/env python3

import os
import sys
import json
import urllib.request
import urllib.error
from datetime import datetime


SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
ERROR_LOG = "/var/ossec/logs/slack_errors.log"

# Only notify for these original alert types.
# This prevents Slack from being flooded by every generic ML HIGH alert.
IMPORTANT_ORIGINAL_RULES = {
    "100212": "sqlmap User-Agent",
    "100302": "Suricata sqlmap detection",
    "100301": "Suricata /etc/passwd probe",
    "31164": "SQL injection",
    "31103": "SQL injection",
    "31101": "Web traversal / 400 probe",
    "2502": "Repeated SSH password failure",
    "100100": "Hydra / brute-force summary"
}

IMPORTANT_ORIGINAL_RULES = {
    str(k).strip(): v for k, v in IMPORTANT_ORIGINAL_RULES.items()
}

def log_error(message):
    try:
        with open(ERROR_LOG, "a") as f:
            f.write(f"{datetime.utcnow().isoformat()} {message}\n")
    except Exception:
        pass

def send_slack(message):
    if not SLACK_WEBHOOK:
        log_error("SLACK_WEBHOOK_URL environment variable is not configured")
        return

    payload = json.dumps({"text": message}).encode("utf-8")

    req = urllib.request.Request(
        SLACK_WEBHOOK,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            response_body = response.read().decode("utf-8", errors="ignore")
            log_error(f"Slack sent OK | status={response.status} | response={response_body}")
    except urllib.error.HTTPError as e:
        log_error(f"Slack HTTP error: {e.code} {e.reason}")
    except Exception as e:
        log_error(f"Slack error: {e}")

def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    alert_file = sys.argv[1]

    try:
        with open(alert_file, "r") as f:
            alert = json.load(f)
    except Exception as e:
        log_error(f"Could not read alert file: {e}")
        sys.exit(1)

    if "_source" in alert:
        alert = alert["_source"]

    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}
    agent = alert.get("agent", {}) or {}

    ml_rule_id = str(rule.get("id", "")).strip()
    ml_rule_desc = rule.get("description", "No description")


    final_priority = str(data.get("status", "UNKNOWN")).strip().upper()
    confidence = str(
    data.get("extra_data")
    or data.get("confidence")
    or data.get("ml_confidence")
    or "N/A"
    )
    srcip = str(data.get("srcip", "unknown"))
    original_rule_id = str(
    data.get("id")
    or data.get("rule_id")
    or data.get("original_rule")
    or data.get("original_rule_id")
    or rule.get("id")
    or "unknown"
    ).strip()
    original_desc = str(
    data.get("url")
    or data.get("description")
    or data.get("desc")
    or ml_rule_desc
    )
    original_agent = str(data.get("hostname", agent.get("name", "unknown")))
    safety_action = str(data.get("action", "N/A")).strip().upper()
    reason = str(data.get("reason", ""))

 

    mitre_tactic = str(data.get("mitre_tactic", "Unmapped"))
    mitre_id = str(data.get("mitre_id", "N/A"))
    mitre_technique = str(data.get("mitre_technique", "N/A"))

   
    # Notify for:
    # 1. Existing auto-response candidates under ML rule 110010.
    # 2. Confirmed brute-force summaries under ML rule 110001.
    # Generic SSH failures remain excluded.

    BRUTE_FORCE_SUMMARY_RULES = {
        "2502",
        "100100"
    }

    is_auto_response_alert = (
        ml_rule_id == "110010"
    )

    is_confirmed_brute_force_alert = (
        ml_rule_id == "110001"
        and original_rule_id in BRUTE_FORCE_SUMMARY_RULES
        and final_priority == "HIGH"
    )

    if not (
        is_auto_response_alert
        or is_confirmed_brute_force_alert
    ):
        sys.exit(0)

    # Avoid Slack spam from generic auth/noise unless it is a strong brute-force rule.
    
    if original_rule_id not in IMPORTANT_ORIGINAL_RULES:
        sys.exit(0)

    if safety_action == "AUTO_BLOCK_CANDIDATE":
        label = "AUTO-BLOCK CANDIDATE"
    elif safety_action == "OVERRIDE":
        label = "SAFETY OVERRIDE"
    elif original_rule_id in {"2502", "100100"}:
        label = "BRUTE FORCE / REPEATED AUTH"
    else:
        label = "HIGH PRIORITY ML ALERT"

    attack_type = IMPORTANT_ORIGINAL_RULES.get(original_rule_id, "Auto-block candidate alert")    
    
    message = (
        f"*{label}*\n"
        f"*Attack Type:* {attack_type}\n"
        f"*Final Priority:* {final_priority}\n"
        f"*Confidence:* {confidence}\n"
        f"*Source IP:* {srcip}\n"
        f"*Agent:* {original_agent}\n"
        f"*Original Rule ID:* {original_rule_id}\n"
        f"*ML Rule ID:* {ml_rule_id}\n"
        f"*Safety Action:* {safety_action}\n"
        f"*MITRE Tactic:* {mitre_tactic}\n"
        f"*MITRE Technique:* {mitre_id} - {mitre_technique}\n"
        f"*Reason:* {reason if reason else 'N/A'}\n"
        f"*Description:* {original_desc}"
)
    send_slack(message)

if __name__ == "__main__":
    main()

