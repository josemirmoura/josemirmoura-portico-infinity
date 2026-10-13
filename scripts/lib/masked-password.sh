#!/usr/bin/env bash
# Mask only interactive OAuth operator password prompts with one * per typed
# character. Keep the secret in a caller variable, never argv/stdout/logs.
# The caller MUST require an interactive TTY and leave shell tracing off.
vps_agent_read_masked_password() {
  local target="$1" prompt="$2" value="" key=""
  printf "%s" "$prompt" >&2
  while :; do
    if ! IFS= read -r -s -n1 key; then
      printf "\n" >&2
      return 1
    fi
    case "$key" in
      "") break ;;
      $'\177'|$'\b')
        if [ -n "$value" ]; then
          value="${value%?}"
          printf '\b \b' >&2
        fi
        ;;
      $'\025')
        # Ctrl+U clears the current line, without printing the password.
        while [ -n "$value" ]; do
          value="${value%?}"
          printf '\b \b' >&2
        done
        ;;
      *)
        value+="$key"
        printf '*' >&2
        ;;
    esac
  done
  printf '\n' >&2
  printf -v "$target" "%s" "$value"
}
