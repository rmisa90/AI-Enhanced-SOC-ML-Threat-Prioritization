#!/usr/bin/env python3

import sys
import json
import os
import time
from datetime import datetime

STATE_FILE = "/var/ossec/logs/ml_campaign_state.json"
CAMPAIGN_LOG = "/var/ossec/logs/ml_campaign.log"

WINDOW_SECONDS = 600  # 10 minutes

IMPORTANT_TACTICS = {
    "Initial Access",
    "Discovery",
    "Credential Access",
    "Defense Evasion"
}

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}

    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception:
        pass

def write_campaign_log(message):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with open(CAMPAIGN_LOG, "a") as f:
        f.write(f"{timestamp} INFO {message}\n")

def clean_old_events(events, now):
    return [e for e in events if now - int(e.get("time", 0)) <= WINDOW_SECONDS]

def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    alert_file = sys.argv[1]

    try:
        with open(alert_file, "r") as f:
            alert = json.load(f)
    except Exception:
        sys.exit(1)

    if "_source" in alert:
        alert = alert["_source"]

    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}

    ml_rule_id = str(rule.get("id", ""))
    final_priority = str(data.get("status", "UNKNOWN"))
    ml_priority = str(data.get("ml_status", "UNKNOWN"))
    srcip = str(data.get("srcip", "unknown"))
    original_rule_id = str(data.get("id", "unknown"))
    original_desc = str(data.get("url", "unknown"))
    tactic = str(data.get("mitre_tactic", "N/A"))
    technique_id = str(data.get("mitre_id", "N/A"))
    technique = str(data.get("mitre_technique", "N/A"))
    confidence = str(data.get("extra_data", "N/A"))
    hostname = str(data.get("hostname", "unknown"))

    # Only correlate final HIGH ML alerts.
    if ml_rule_id != "110010":
        sys.exit(0)

    if final_priority != "HIGH":
        sys.exit(0)

    if srcip in {"unknown", "0.0.0.0", "-", ""}:
        sys.exit(0)

    if tactic == "N/A":
        sys.exit(0)

    now = int(time.time())

    state = load_state()

    if srcip not in state:
        state[srcip] = []

    state[srcip] = clean_old_events(state[srcip], now)

    event = {
        "time": now,
        "tactic": tactic,
        "technique_id": technique_id,
        "technique": technique,
        "rule_id": original_rule_id,
        "description": original_desc,
        "confidence": confidence,
        "hostname": hostname
    }

    state[srcip].append(event)

    # Calculate campaign properties
    recent_events = state[srcip]
    tactics = sorted(set(e["tactic"] for e in recent_events if e["tactic"] in IMPORTANT_TACTICS))
    rule_ids = sorted(set(e["rule_id"] for e in recent_events))
    event_count = len(recent_events)

    campaign_type = "NONE"
    severity = "LOW"

    if len(tactics) >= 3:
        campaign_type = "MULTI_STAGE_ATTACK_CAMPAIGN"
        severity = "CRITICAL"
    elif "Initial Access" in tactics and "Discovery" in tactics:
        campaign_type = "WEB_ATTACK_CHAIN"
        severity = "HIGH"
    elif "Credential Access" in tactics and event_count >= 2:
        campaign_type = "BRUTE_FORCE_CAMPAIGN"
        severity = "HIGH"
    elif event_count >= 3:
        campaign_type = "REPEATED_HIGH_ALERTS"
        severity = "HIGH"

    if campaign_type != "NONE":
        write_campaign_log(
            f"CAMPAIGN_DETECTED=YES | "
            f"CAMPAIGN_TYPE={campaign_type} | "
            f"CAMPAIGN_SEVERITY={severity} | "
            f"SRCIP={srcip} | "
            f"EVENT_COUNT={event_count} | "
            f"TACTICS={','.join(tactics)} | "
            f"RULE_IDS={','.join(rule_ids)} | "
            f"WINDOW_SECONDS={WINDOW_SECONDS} | "
            f"LAST_TACTIC={tactic} | "
            f"LAST_TECHNIQUE_ID={technique_id} | "
            f"LAST_TECHNIQUE={technique} | "
            f"LAST_DESC={original_desc}"
        )

    save_state(state)

if __name__ == "__main__":
    main()