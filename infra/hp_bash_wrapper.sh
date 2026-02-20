#!/bin/bash
# hp_bash_wrapper.sh — wrapper that logs interactive commands
LOGDIR=/var/log/hp/sessions
mkdir -p "$LOGDIR"
SESSION_FILE="$LOGDIR/$(hostname)-$(date +%s)-$$.log"
if command -v script >/dev/null 2>&1; then
  exec script -q -f "$SESSION_FILE" /bin/bash --login
else
  export PROMPT_COMMAND='echo "$(date -Iseconds) CMD:$BASH_COMMAND" >> '"$SESSION_FILE"
  exec /bin/bash --login
fi
