#!/usr/bin/env bash

# Canonical product identity for operator-facing terminal scripts.
# Do not source this file from machine-readable APIs or JSON-producing commands.

VPS_AGENT_PRODUCT_NAME="Portico MCP"
VPS_AGENT_PRODUCT_SLUG="portico-mcp"
VPS_AGENT_AUTHOR_NAME="Josemir Moura"
VPS_AGENT_AUTHOR_GITHUB="github.com/josemirmoura"

vps_agent_repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." >/dev/null 2>&1 && pwd
}

vps_agent_version() {
  local root
  root="$(vps_agent_repo_root)"
  if [ -r "$root/VERSION" ]; then
    tr -d '[:space:]' <"$root/VERSION"
    return
  fi
  if command -v git >/dev/null 2>&1 && git -C "$root" describe --tags --always --dirty >/dev/null 2>&1; then
    git -C "$root" describe --tags --always --dirty
    return
  fi
  printf 'unknown'
}

vps_agent_normalize_lang() {
  local raw="${1:-}"
  raw="${raw%%.*}"
  raw="${raw//@/-}"
  case "$raw" in
    pt|pt_BR|pt-BR|pt_*) printf 'pt-BR' ;;
    en|en_US|en-US|en_GB|en-GB|en_*) printf 'en' ;;
    *) printf 'en' ;;
  esac
}

vps_agent_init_language() {
  local explicit="${1:-}"
  local detected
  if [ -n "$explicit" ]; then
    detected="$explicit"
  elif [ -n "${VPS_AGENT_LANG:-}" ]; then
    detected="$VPS_AGENT_LANG"
  elif [ -n "${LC_ALL:-}" ]; then
    detected="$LC_ALL"
  elif [ -n "${LC_MESSAGES:-}" ]; then
    detected="$LC_MESSAGES"
  else
    detected="${LANG:-en}"
  fi
  VPS_AGENT_LANG="$(vps_agent_normalize_lang "$detected")"
  export VPS_AGENT_LANG
}

vps_agent_is_pt_br() {
  [ "${VPS_AGENT_LANG:-en}" = "pt-BR" ]
}

vps_agent_text() {
  local en="$1"
  local pt="$2"
  if vps_agent_is_pt_br; then
    printf '%s' "$pt"
  else
    printf '%s' "$en"
  fi
}

vps_agent_language_label() {
  if vps_agent_is_pt_br; then
    printf 'Português (Brasil)'
  else
    printf 'English'
  fi
}

vps_agent_confirm_language() {
  [ -t 0 ] || return 0
  [ "${VPS_AGENT_LANG_EXPLICIT:-0}" = "1" ] && return 0

  local answer=""
  if vps_agent_is_pt_br; then
    printf 'Idioma detectado: Português (Brasil)\n'
    printf '[Enter] continuar | [E] English: '
    read -r answer
    case "$answer" in
      e|E|en|EN|english|English) VPS_AGENT_LANG="en"; export VPS_AGENT_LANG ;;
    esac
  else
    printf 'Detected language: English\n'
    printf '[Enter] continue | [P] Português (Brasil): '
    read -r answer
    case "$answer" in
      p|P|pt|PT|pt-br|pt-BR) VPS_AGENT_LANG="pt-BR"; export VPS_AGENT_LANG ;;
    esac
  fi
  printf '\n'
}

vps_agent_tagline() {
  vps_agent_text     "Secure MCP Gateway for Linux Hosts"     "Gateway MCP seguro para hosts Linux"
}

vps_agent_author_line() {
  vps_agent_text     "Made by $VPS_AGENT_AUTHOR_NAME | $VPS_AGENT_AUTHOR_GITHUB"     "Feito por $VPS_AGENT_AUTHOR_NAME | $VPS_AGENT_AUTHOR_GITHUB"
}

vps_agent_banner() {
  local version locale_name terminal_width
  version="$(vps_agent_version)"
  locale_name="${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"
  terminal_width="${COLUMNS:-80}"

  printf '\n+------------------------------------------------------------+\n'
  # The five-line logo uses single-column Unicode blocks. Fall back to an
  # ASCII header on non-UTF-8 or narrow terminals, or when explicitly asked.
  if [ "${VPS_AGENT_BANNER_ASCII:-0}" != "1" ] &&
     [[ "$locale_name" == *[Uu][Tt][Ff]-8* || "$locale_name" == *[Uu][Tt][Ff]8* ]] &&
     [[ "$terminal_width" =~ ^[0-9]+$ ]] && [ "$terminal_width" -ge 62 ]; then
    while IFS= read -r line; do
      printf '| %-58s |\n' "$line"
    done <<'PORTICO_LOGO'
  ██████   ██████  ██████  ████████ ██  ██████   ██████
  ██   ██ ██    ██ ██   ██    ██    ██ ██       ██    ██
  ██████  ██    ██ ██████     ██    ██ ██       ██    ██
  ██      ██    ██ ██   ██    ██    ██ ██       ██    ██
  ██       ██████  ██   ██    ██    ██  ██████   ██████
PORTICO_LOGO
  else
    printf '| %-58s |\n' 'PORTICO MCP'
  fi
  printf '| %-58s |\n' ''
  # Identity lines are intentionally invariant, even in the pt-BR installer.
  printf '| %-58s |\n' 'Secure MCP Gateway for Linux Hosts'
  printf '| %-58s |\n' "Made by $VPS_AGENT_AUTHOR_NAME | $VPS_AGENT_AUTHOR_GITHUB"
  printf '| %-58s |\n' "Version: $version"
  printf '+------------------------------------------------------------+\n\n'
}

vps_agent_step() {
  printf '\n==> %s\n' "$*"
}

vps_agent_note() {
  printf '    %s\n' "$*"
}
