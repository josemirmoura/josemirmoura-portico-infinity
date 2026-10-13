#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=scripts/lib/product.sh
source scripts/lib/product.sh
vps_agent_init_language ""

if [ ! -f .env ]; then
  echo "$(vps_agent_text 'Missing .env. Run scripts/init.sh first.' 'Arquivo .env ausente. Execute scripts/init.sh primeiro.')" >&2
  exit 1
fi
set -a
. ./.env
set +a

PUBLIC_URL="${VPS_AGENT_PUBLIC_URL:-}"
SUBJECT="${VPS_AGENT_SUBJECT:-operator}"
MARKER="state/integrated-auth.json"

if [ -z "$PUBLIC_URL" ]; then
  echo "$(vps_agent_text 'VPS_AGENT_PUBLIC_URL is not configured.' 'VPS_AGENT_PUBLIC_URL não está configurada.')" >&2
  exit 1
fi

if [ "${VPS_AGENT_AUTH_MODE:-static}" != "integrated" ]; then
  echo "$(vps_agent_text     'ChatGPT public connection requires the integrated OAuth path.'     'A conexão pública com o ChatGPT requer o fluxo OAuth integrado.')" >&2
  exit 1
fi

operator_username="vps-operator"
operator_email=""
if [ -s "$MARKER" ]; then
  readarray -t identity < <(python3 - "$MARKER" <<'PY'
import json,sys
try:
    data=json.load(open(sys.argv[1]))
except Exception:
    data={}
print(data.get("username","vps-operator"))
print(data.get("email",""))
PY
  )
  operator_username="${identity[0]:-vps-operator}"
  operator_email="${identity[1]:-}"
fi

bash ./scripts/verify-public.sh

wait_tool=(docker compose exec -T broker /usr/local/bin/vps-agent wait-tool --subject "$SUBJECT" --tool system.info)
BASELINE="$("${wait_tool[@]}" --baseline-only)"
[[ "$BASELINE" =~ ^[0-9]+$ ]] || {
  echo "$(vps_agent_text 'ERROR: could not establish the audit verification baseline.' 'ERRO: não foi possível estabelecer a linha de base da auditoria.')" >&2
  exit 1
}

show_tutorial() {
  local documentation_url documentation_ref
  # Link to the exact checked-out code, including unmerged RC candidates.
  # Only use 'main' if the distributor omitted Git metadata.
  documentation_ref="$(git rev-parse --verify HEAD 2>/dev/null || printf 'main')"
  echo
  if vps_agent_is_pt_br; then
    documentation_url="https://github.com/josemirmoura/mcp-vps-agent-gateway/blob/${documentation_ref}/docs/connect-ai-clients.pt-BR.md"
    cat <<EOF
=== Portico MCP | Conectar clientes de IA ===

Endereço MCP da VPS:
  $PUBLIC_URL

Guia de conexão no GitHub (ChatGPT, Claude, Cursor, VS Code/Copilot):
  $documentation_url

Operador OAuth: $operator_username

Conclua a conexão no cliente de IA escolhido usando OAuth e a senha
do operador que você criou. Nunca use a senha SSH/root da VPS.

Para finalizar o E2E Community atual, conecte o ChatGPT e solicite:
  Call system.info on my VPS MCP and tell me the hostname.

Depois volte a este terminal e pressione Enter para verificar a chamada
autenticada e auditada pelo Broker. O registro de um cliente, sozinho,
não comprova a instalação completa.
EOF
  else
    documentation_url="https://github.com/josemirmoura/mcp-vps-agent-gateway/blob/${documentation_ref}/docs/connect-ai-clients.md"
    cat <<EOF
=== Portico MCP | Connect AI clients ===

VPS MCP endpoint:
  $PUBLIC_URL

GitHub connection guide (ChatGPT, Claude, Cursor, VS Code/Copilot):
  $documentation_url

OAuth operator: $operator_username

Connect your chosen AI client using OAuth and the dedicated operator
password created during setup. Never use VPS SSH/root credentials.

To finish the current Community E2E gate, connect ChatGPT and request:
  Call system.info on my VPS MCP and tell me the hostname.

Then return to this terminal and press Enter to verify the authenticated
Broker-audited call. Registering a client alone does not complete installation.
EOF
  fi
}

verify_now() {
  "${wait_tool[@]}" --after-seq "$BASELINE" --timeout 1s --poll 200ms --quiet
}

show_tutorial

if [ ! -t 0 ]; then
  echo "$(vps_agent_text     'Waiting for the real audited ChatGPT call in non-interactive mode...'     'Aguardando a chamada real e auditada do ChatGPT em modo não interativo...')"
  "${wait_tool[@]}" --after-seq "$BASELINE" --timeout "${VPS_AGENT_CHATGPT_VERIFY_TIMEOUT:-10m}"
else
  while :; do
    echo
    if vps_agent_is_pt_br; then
      printf '[Enter] verificar conexão  [T] mostrar link da documentação  [S] sair: '
    else
      printf '[Enter] verify connection  [T] show documentation link  [Q] quit: '
    fi
    read -r answer

    case "$answer" in
      t|T)
        show_tutorial
        continue
        ;;
      s|S|q|Q)
        echo "$(vps_agent_text           'Leaving without completing installation. Run scripts/connect-chatgpt.sh again when ready.'           'Saindo sem concluir a instalação. Execute scripts/connect-chatgpt.sh novamente quando estiver pronto.')"
        exit 2
        ;;
      "")
        if verify_now; then
          break
        fi
        echo
        if vps_agent_is_pt_br; then
          cat <<'EOF'
Ainda não detectamos a chamada system.info do ChatGPT.

Confira se:
- o app MCP foi criado;
- o OAuth foi concluído;
- o Portico MCP está selecionado no chat;
- a mensagem de teste foi realmente enviada.

Nada foi perdido. Faça os ajustes necessários e pressione Enter para tentar novamente.
EOF
        else
          cat <<'EOF'
We have not detected the ChatGPT system.info call yet.

Check that:
- the MCP app was created;
- OAuth was completed;
- Portico MCP is selected in the chat;
- the test message was actually sent.

Nothing was lost. Fix anything needed and press Enter to try again.
EOF
        fi
        ;;
      *)
        echo "$(vps_agent_text 'Choose Enter, T or S.' 'Escolha Enter, T ou S.')"
        ;;
    esac
  done
fi

mkdir -p state
printf '{"verified_at":"%s","endpoint":"%s","subject":"%s","after_audit_seq":%s}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PUBLIC_URL" "$SUBJECT" "$BASELINE" \
  > state/chatgpt-verified.json
chmod 600 state/chatgpt-verified.json

echo
echo "$(vps_agent_text 'CHATGPT WEB CONNECTION VERIFIED' 'CONEXÃO COM O CHATGPT WEB VERIFICADA')"
echo "$(vps_agent_text 'INSTALLATION COMPLETE' 'INSTALAÇÃO CONCLUÍDA')"
