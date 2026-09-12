#!/bin/bash

LOCAL=$(dirname "$0")
cd "$LOCAL" || exit 1
cd ../ || exit 1
PWD=$(pwd)

LOG_FILE="${PWD}/../logs/active-responses.log"
COUNTER_DIR="${PWD}/../active-response/ml_counters"

mkdir -p "$COUNTER_DIR"

read INPUT_JSON

SRCIP=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    alert = data.get('parameters', {}).get('alert', {})
    d = alert.get('data', {}) or {}
    ip = d.get('srcip') or d.get('src_ip') or d.get('source_ip') or ''
    print(str(ip).strip())
except Exception:
    print('')
" 2>/dev/null)

ACTION=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('command', 'add'))
except Exception:
    print('add')
" 2>/dev/null)


ORIG_RULE_ID=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    alert = data.get('parameters', {}).get('alert', {})
    d = alert.get('data', {}) or {}
    r = alert.get('rule', {}) or {}
    rid = (
        d.get('id')
        or d.get('rule_id')
        or d.get('original_rule')
        or d.get('original_rule_id')
        or r.get('id')
        or ''
    )

    print(str(rid).strip())
except Exception:
    print('')
" 2>/dev/null)

DESC=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    alert = data.get('parameters', {}).get('alert', {})
    d = alert.get('data', {}) or {}
    print(str(d.get('url', '')).strip())
except Exception:
    print('')
" 2>/dev/null)

echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK received action=$ACTION ip=$SRCIP original_rule=$ORIG_RULE_ID desc=$DESC" >> "$LOG_FILE"

# If Wazuh sends delete action after timeout, unblock.
if [ "$ACTION" = "delete" ]; then
    if [ -n "$SRCIP" ] && /sbin/iptables -C INPUT -s "$SRCIP" -j DROP 2>/dev/null; then
        /sbin/iptables -D INPUT -s "$SRCIP" -j DROP
        echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK UNBLOCKED ip=$SRCIP" >> "$LOG_FILE"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK unblock skipped — rule not found ip=$SRCIP" >> "$LOG_FILE"
    fi
    exit 0
fi

# Skip empty or unknown source IP.
if [ -z "$SRCIP" ] || [ "$SRCIP" = "unknown" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK skipped — missing or unknown srcip" >> "$LOG_FILE"
    exit 0
fi

# Safety exclusions: never block local or protected lab systems.
case "$SRCIP" in
    127.*|0.0.0.0)
        echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK skipped — loopback/local ip=$SRCIP" >> "$LOG_FILE"
        exit 0
        ;;
esac

BLOCK_ALLOWED="no"
BLOCK_REASON=""

# 1. SQL injection: block immediately.
case "$ORIG_RULE_ID" in
    31164|31103)
        BLOCK_ALLOWED="yes"
        BLOCK_REASON="SQL injection payload"
        ;;
esac

# 3. Repeated web probing/multiple 400 errors: block immediately.
case "$ORIG_RULE_ID" in
    31115)
        BLOCK_ALLOWED="yes"
        BLOCK_REASON="repeated suspicious web probing"
        ;;
esac

# 4. Single directory traversal /etc/passwd rule:
# Do not block on the first event. Block only if repeated from same IP.
if [ "$ORIG_RULE_ID" = "31101" ]; then
    COUNTER_FILE="$COUNTER_DIR/traversal_${SRCIP}.log"
    NOW=$(date +%s)

    echo "$NOW" >> "$COUNTER_FILE"

    # Keep only events from last 5 minutes.
    awk -v now="$NOW" '$1 >= now-300' "$COUNTER_FILE" > "${COUNTER_FILE}.tmp"
    mv "${COUNTER_FILE}.tmp" "$COUNTER_FILE"

    COUNT=$(wc -l < "$COUNTER_FILE")

    echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK traversal_count ip=$SRCIP count=$COUNT" >> "$LOG_FILE"

    if [ "$COUNT" -ge 3 ]; then
        BLOCK_ALLOWED="yes"
        BLOCK_REASON="repeated directory traversal or sensitive file probing"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK skipped — single traversal/probe, review first ip=$SRCIP count=$COUNT" >> "$LOG_FILE"
        exit 0
    fi
fi

# 5. SSH brute-force:
# Do not block single failed login events. Block only after repeated auth-related alerts.
case "$ORIG_RULE_ID" in
    2502|5710|5503)
        COUNTER_FILE="$COUNTER_DIR/ssh_${SRCIP}.log"
        NOW=$(date +%s)

        echo "$NOW $ORIG_RULE_ID" >> "$COUNTER_FILE"

        # Keep only events from last 5 minutes.
        awk -v now="$NOW" '$1 >= now-300' "$COUNTER_FILE" > "${COUNTER_FILE}.tmp"
        mv "${COUNTER_FILE}.tmp" "$COUNTER_FILE"

        COUNT=$(wc -l < "$COUNTER_FILE")

        echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK ssh_count ip=$SRCIP count=$COUNT" >> "$LOG_FILE"

        if [ "$COUNT" -ge 6 ]; then
            BLOCK_ALLOWED="yes"
            BLOCK_REASON="clear SSH brute-force pattern"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK skipped — SSH failures below brute-force threshold ip=$SRCIP count=$COUNT" >> "$LOG_FILE"
            exit 0
        fi
        ;;
esac

# If original rule is not approved, skip blocking.
if [ "$BLOCK_ALLOWED" != "yes" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK skipped — rule_id=$ORIG_RULE_ID not approved for auto-block" >> "$LOG_FILE"
    exit 0
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK approved ip=$SRCIP rule_id=$ORIG_RULE_ID reason=$BLOCK_REASON" >> "$LOG_FILE"

# Apply iptables block.
if /sbin/iptables -C INPUT -s "$SRCIP" -j DROP 2>/dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK already blocked ip=$SRCIP" >> "$LOG_FILE"
else
    /sbin/iptables -I INPUT -s "$SRCIP" -j DROP
    echo "$(date '+%Y-%m-%d %H:%M:%S') ML_BLOCK BLOCKED ip=$SRCIP reason=$BLOCK_REASON" >> "$LOG_FILE"
fi

exit 0
