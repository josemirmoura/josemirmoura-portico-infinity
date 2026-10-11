# Gate C 2026-07-28: decisao de aplicabilidade (proposta ao auditor independente)

**Escopo:** Community publica, um cliente MCP compativel por computador Linux Scoped. Nao se aplica ao cliente MCP, nem a um authorization server implementado pelo Portico. O Broker, e nao o modelo de IA, decide acesso. Este documento nao aprova o release.

## Fontes normativas imutaveis

- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/logging
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- https://github.com/modelcontextprotocol/conformance/blob/c37eec888e1c6ff140af79987a40008548b7cc5f/requirements/2026-07-28.yaml

## Analise estrita por funcionalidade realmente anunciada

| Controle | Aplicabilidade | Prova ou decisao | Risco residual |
| --- | --- | --- | --- |
| Base: JSON-RPC, request _meta, versao e headers | MUST | Handler normal, workflow de perfil e negative regressions Go | Testes de envelope malformado e interacoes incomuns continuam PARCIAIS |
| Streamable HTTP POST; response JSON ou SSE | MUST | O servidor pode escolher JSON ou SSE por chamada. Community usa JSONResponse=true. Nao implementar SSE inventado para passar em teste com esse nome | Quando algum caminho real devolver SSE, testar framing, X-Accel-Buffering e cancelamento desse caminho |
| Cancelamento | MUST onde houver fluxo em curso | Teste real HTTP request context -> Executor, fail se desconexao nao cancela | Cancelamento de trabalho remoto Broker que ja executa exige politica e testes especificos |
| tools/list e tools/call | MUST do perfil oferecido | Catálogo real, metadata e schema 2020-12 de cada item resolvidos sem baixar refs, ordenacao estavel e structuredContent do system.info | Composicao/condicionais arbitrarias e saidas de todas as ferramentas ainda exigem avaliacao |
| inputSchema | MUST do perfil oferecido | Root object obrigatorio, dialect JSON Schema 2020-12, refs locais e Resolve testados | Nao declarar prova de validacao exaustiva de todas combinacoes |
| outputSchema | Condicional | Se existir, verificar schema e structuredContent correspondente. Root de output pode ser de qualquer tipo em 2026 | Amostras de todas as ferramentas ainda nao executadas em Broker |
| MCP logging | Opcional e deprecated | Community nao gera notifications/message para clientes; flag `logging` removida da publicidade | Auditoria append-only do Broker e logs de infraestrutura permanecem obrigacoes do produto, nao da feature de logging MCP |
| Legacy logging/setLevel | Nao aplicavel a 2026-07-28 | Controle C31 anterior exigia metodo obsoleto; em 2026 a negociacao e por `_meta.io.modelcontextprotocol/logLevel` quando logging e usado | Nao reintroduzir metodo antigo nem afirmar teste sobre ele |
| completion/complete | Opcional, nao anunciado | Resposta 404 + JSON-RPC -32601 para metodo indisponivel e correta | Runner congelado inclui cenario; FAIL bruto permanece e nao prova descumprimento universal |
| MRTR InputRequiredResult | Opcional por ferramenta | Ferramentas MAY retornar input_required, apenas quando cliente suporta os input methods. Approvals HTTPS do operador nao sao permissoes automaticas do cliente | Extensao/capacidades anunciadas precisam ser revisadas contra testes de assinatura, input state, repeticao, deny/revoke e client support |
| subscriptions/listen | Condicional | Produto oferece listas estaticas sem listChanged. Nao anunciar eventos que nao emite | Se houver stream listen anunciado, provar encerramento e isolamento |
| OAuth resource server | MUST no deployment integrado | JWT/introspection, 401 invalid token, 403 insufficient scope, Bearer challenge metadata e TLS fixture com CA validada | HTTPS/introspection real atras do Docker/Traefik e rollback RC7 em clone de destino nao provados |

## Evidencias negativas adicionais do Gateway normal

- `internal/gateway/mcp_gate_c_malformed_jsonrpc_test.go`: POSTs com JSON inválido, versionamento incorreto, método ausente, parâmetros e IDs inválidos retornam erro estruturado antes do Executor. Erros de argumentos de ferramentas podem corretamente retornar `tools/call` com `isError: true`, desde que nenhuma ação alcance o Broker.
- `internal/gateway/mcp_jsonrpc_shape.go`: guard de estrutura JSON-RPC após autenticação e limites de concorrência/rate-limit, antes da SDK. Não altera o catálogo e não concede autoridade. Limite de leitura igual a 1 MiB do SDK.
- `internal/gateway/mcp_gate_c_mrtr_navigation_test.go`: verifica HMAC, expiração, sujeito e recurso; a aceitação nativa não concede acesso, somente consulta `permissions.approval_status`.
- Esta cobertura permanece **PARCIAL**: interpretação de todo SHOULD da especificação, todos os tipos de conteúdo, interações de MRTR com clientes reais e rollback de operações Broker em andamento não foram certificados.

## Regras de provas e aceites

1. Separar test suite oficial congelada (resultado **literal**) da prova de requisitos **aplicaveis** do Gateway normal. Nao alterar checks.json, nao criar test_* no runtime e nao mascarar falsos positivos.
2. O resultado anterior da suite no Gateway distribuivel foi 8 PASS, 2 FAIL, 3 SKIPPED, 24 NOT_TESTED; fixture 35/1/1/0. Ambos release_gate_passed=false. Os dois FAIL nominais sao completion opcional nao anunciada e MRTR multi-round dependente de fixture sintética. Nova CI deve preservar a mesma distincao.
3. Gate C nao fecha com este documento. Exige parecer independente no SHA de staging congelado, cobertura dos MUST aplicaveis, declaracao dos SHOULD e riscos residuais. A prova TLS/CA/upgrade/rollback numa topologia equivalente a VPS real pode ser condicionante de liberacao, mas nunca e substituida por mock CI.
4. Gate E e separado: login ChatGPT, Central HTTPS, operador real, negacao, revogacao e retomada nao se tornam validos por teste Go.
5. Integrar alteracoes apenas em staging com CI verde; main, VPS, DNS, releases e seguranca de producao permanecem intactos ate autorizacao explicita.

## Inventario mecanico

Ver docs/mcp-gate-c-normative-controls.json e tests/scripts/test_mcp_gate_c_normative_controls.py. Status LAB_PASS significa cobertura focal de laboratorio, nao certificacao universal.
