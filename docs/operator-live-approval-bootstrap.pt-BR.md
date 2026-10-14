# Homologação da autorização HTTPS na instalação existente

**Contexto:** Issue #189. Antes de qualquer E2E de remoção/reinstalação,
consolidar autorizações de pastas na instalação funcional. O código da
Central já existe; sua ativação é opcional e diferente do login OAuth.

## Contrato

- ChatGPT solicita permissão temporal para **pasta específica**, por exemplo
  uma pasta experimental dentro de `/opt`.
- Gateway cria pedido `apr_...` e retorna `operator_approval_url` sob HTTPS.
- Proprietário abre em outra aba, autentica-se separadamente e
  aprova/nega. ChatGPT consulta `permissions.approval_status`; só o Broker
  confirma o grant. A aprovação da chamada MCP não dá acesso ao filesystem.
- **O teto completo /opt**, autorizações permanentes e elevação geral
  permanecem fora do canal HTTPS simplificado. Não afrouxar essa política
  para facilitar o teste.
- Sem Central válida o fallback CLI/SSH continua fail-closed; nunca simular
  aprovação automática ou expor tokens no chat.

## 1. Diagnóstico inicial em produção, exclusivamente leitura

No **terminal do operador autenticado**, na checkout realmente instalada.
Não enviar `.env` ou saída bruta de `docker inspect` para o chat.

```bash
cd /home/jmour/mcp-vps-agent-gateway || exit 1
git rev-parse HEAD
git status --short
python3 scripts/operator-approval-readiness.py
python3 scripts/operator-approval-runtime-readiness.py
```

O último script apenas consulta `docker ps` e `docker inspect`, filtra
serviços Docker Compose pelo projeto `mcp-vps-agent`, compara valores
sensíveis **em memória**, mas só imprime booleanos e estado. Não executa
shell, não imprime URL concreta nem qualquer segredo. Se o script ainda não
estiver na checkout, **não substituir por `docker inspect` colado no chat**;
ele será disponibilizado após revisão da PR #190 (ou a PR correspondente).

Possíveis diagnósticos:

- `GATEWAY_MISSING_OPERATOR_URL`: URL HTTPS não propagada ao contêiner
  Gateway; configurar o projeto e aplicar atualização mínima controlada.
- `OPERATOR_PORTAL_NOT_RUNNING`: o serviço opt-in da Central não está ativo,
  mesmo que o Gateway esteja conectado ao ChatGPT.
- `PORTAL_CONFIGURATION_INCOMPLETE`: identidade, token restrito,
  origem HTTPS ou router do portal não coincidem entre componentes.
- `CONFIGURED_NOT_BROWSER_VERIFIED`: apenas configurações de contêiner
  parecem prontas. **Não é prova** de DNS/TLS, login real ou autorização.
- `GATEWAY_OR_BROKER_NOT_RUNNING`/`UNAVAILABLE`: não executar promoção;
  investigar sob acesso administrativo separado.

## 2. Mudança pequena, reversível e supervisionada

Após o diagnóstico, preparar proposta concreta sem mexer em produção:

1. Fixar o SHA/digest da instalação anterior e a nova versão auditada da
   Community, verificar se a checkout está limpa e listar os overlays
   Compose efetivamente ativos.
2. Inspecionar não secretamente as rotas atuais /mcp, OAuth/ZITADEL e
   Traefik. Verificar que o projeto não será substituído ou recriado inteiro.
3. Planejar backup **verificado** de banco de grants/auditoria, `.env`
   e política em destino protegido fora da checkout. Não enviar materiais
   nem credenciais ao chat.
4. Gerar senha scrypt e token do portal **somente em SSH do operador**,
   via `scripts/operator-portal-credentials.py` quando apropriado.
   Nunca criar, aprovar ou transmitir credenciais pela IA.
5. Preparar modelo com `compose.yaml`,
   `compose.integrated-auth.yaml` e
   `compose.operator-portal.edge.yaml`, respeitando o profile
   `operator-portal`. Validar `docker compose config --quiet`,
   sem imprimir modelo expandido ou segredos.
6. Definir exatamente quais contêineres precisam atualização
   (Gateway, portal e Broker **somente se a credencial do socket exigir**),
   janela de interrupção, histórico de auditoria, rollback e condição STOP.
   **Não usar** `docker compose up` genérico; não tocar em Traefik nem
   ZITADEL se não houver motivo explícito.
7. Fazer alteração somente após decisão específica do operador para essa
   proposta. A autorização para inventário em leitura **não** autoriza
   editar `.env`, criar credenciais ou reiniciar contêineres.

## 3. Aceite real antes do E2E integral

- `GET https://<domínio-validado>/operator` responde sob TLS sem expor
  tokens, e a Central funciona no navegador móvel.
- Pedido de teste `read` por 600 s recebe URL HTTPS e continua `pending`.
- Primeiro NEGAR e confirmar ausência de grant e auditoria registrada.
- Novo pedido, autenticar como operador, APROVAR somente pasta descartável,
  confirmar uma leitura legítima, negar acesso fora de escopo e conferir
  revogação/expiração.
- Validar reentrada no ChatGPT Android e desktop. Se o chat terminar,
  reabrir o turno para consultar `permissions.approval_status`.
- Salvar no GitHub provas não sensíveis, configuração declarativa e o SHA
  aprovado da alteração. Só então retirar o bloqueio pré-E2E de #189.

**Não fazer purge, remover estado, publicar release ou declarar #167 encerrada
nesta etapa.** Ver também `docs/adaptive-approvals-rollout.md`,
`docs/operator-portal-rollout.md`, `docs/operator-approval-fallback.md`.
