# Gate C: controles normativos e contrato verificável da Community

**Revisão:** MCP 2026-07-28. **Upstream de conformance congelado:** `modelcontextprotocol/conformance@c37eec888e1c6ff140af79987a40008548b7cc5f`. **Produto avaliado:** Gateway Community normal, 1 chat compatível ↔ 1 Linux Scoped, sem ferramentas artificiais `test_*`.

Esta página é um pacote de trabalho para **revisor independente**. **Não é certificação**, não afirma cobertura de cada norma e **não autoriza release**. O inventário verificável de 36 controles está em [mcp-gate-c-normative-controls.json](mcp-gate-c-normative-controls.json). O teste `tests/scripts/test_mcp_gate_c_normative_controls.py` rejeita desvios do inventário, arquivos de evidência inexistentes ou falsificação de `RAW_FAIL`.

## Resultado e significado

| Estado | Interpretação |
| --- | --- |
| `LAB_PASS` | Evidência automatizada focada em ambiente descartável, **não** certificação normativa completa |
| `PARTIAL` | Há implementação ou teste, mas falta uma condição ou cobertura normativa |
| `NOT_PROVEN` | Nenhuma prova direta suficiente do comportamento descrito |
| `NOT_ADVERTISED` | Capacidade opcional/condicional não anunciada, com não aplicabilidade sujeita a revisão |
| `REAL_ENV_PENDING` | Depende de ambiente de destino, identidade do operador ou auditor real |
| `RAW_FAIL` | Resultado bruto upstream, preservado sem waiver |

Os controles cobrem **base JSON-RPC; versão e metadados de cada requisição; HTTP stateless e Origin; headers e Base64; OAuth, introspecção e transportes TLS; autorização Scoped e Broker; ferramentas, schemas e rate limit; recursos, prompts, logging e MRTR; controles de publicação/revisão**. A existência de uma linha não substitui revisão normativa independente de todos os SHOULD/MUST aplicáveis.

## Evidência que pode ser reproduzida sem acessar a VPS

1. **HTTP MCP real sem fixtures sintéticas:** `scripts/mcp_community_profile_probe.py`, `internal/gateway/mcp_transport_compat_test.go`, `internal/gateway/mcp_origin_guard_test.go`, `internal/gateway/mcp_origin_default_port_test.go`, `internal/gateway/tool_rate_limit_test.go`.
2. **OAuth e segurança:** `internal/gateway/introspection_transport_security_test.go`, `tests/integration/mcp_oauth_broker_gate_c_test.go` e `tests/integration/mcp_oauth_external_approval_test.go`.
3. **TLS verificado e Gateway real:** `tests/integration/mcp_https_oauth_broker_contract_test.go`. O teste usa certificado e credenciais **somente de laboratório**: introspecção HTTPS com CA adicionada a processo-filho, Gateway HTTPS, endpoint de resource metadata, 401 challenge, bearer/audience/scope inválidos, Origin 403, leitura negada fora da raiz e leitura permitida na raiz pelo Broker/IPC real. **Não testa a CA, a rota Docker ou o domínio da VPS.**
4. **Runner oficial 37 cenários:** `.github/workflows/block2-mcp-lab-fixture.yml`, `scripts/mcp_conformance_matrix.py`, `scripts/mcp_gate_c_diagnostic.py`. Preservar `checks.json`, runner exit e classificações por SHA. O runner não é um gate de release aprovado.
5. **Gate anti-regressão:** `.github/workflows/mcp-community-profile-gate.yml` obriga testes nomeados a retornar PASS, sem skips. Incluir os novos controles e o TLS E2E antes do aceite deste conjunto.

## Evidência congelada anterior e leitura honesta

No [SHA de staging `b01f4d6`](https://github.com/josemirmoura/mcp-vps-agent-gateway/commit/b01f4d6b49dc47da250ed8253b34011ea7aa8b57), **19/19 verificações de GitHub Actions SUCCESS**. O perfil do Gateway normal executou [16 regressões nomeadas](https://github.com/josemirmoura/mcp-vps-agent-gateway/actions/runs/38169559098), sem skip. O [runner oficial bruto](https://github.com/josemirmoura/mcp-vps-agent-gateway/actions/runs/38169559117) retornou:

- Gateway distribuível normal: **8 PASS / 2 FAIL / 3 SKIPPED / 24 NOT_TESTED**; `release_gate_passed=false`.
- Fixture **exclusiva do laboratório**: **35 PASS / 1 FAIL / 1 SKIPPED / 0 NOT_TESTED**; `release_gate_passed=false`.

A não conformidade da suíte congelada **não** é apagada por testes alternativos. O cenário `completion/complete` exige uma capacidade opcional que o Gateway não anuncia. Vários outros cenários usam ferramentas, recursos e prompts de nome sintético, deliberadamente indisponíveis no produto. Isso **não prova** que o Gateway normal satisfaz todos os requisitos normativos; revisão independente deve avaliar separadamente o perfil anunciado, inclusive resultados e ferramentas reais. Não publicar diagnósticos `test_*` para aumentar o placar.

## Checklist do aceite técnico externo (sem intervenção do proprietário nos testes sintéticos)

- [ ] Fixar SHA único, versão SDK e upstream; repetir matriz, workflow do Gateway real e suite congelada.
- [ ] Conferir os 36 controles **contra texto normativo oficial**, expandir lacunas por MUST/SHOULD aplicável, inspecionar esquemas, logs, headers, SSE, cancelamento e recursos expostos. **Não** usar este inventário como assinatura pré-aprovada.
- [ ] Reproduzir ataques de auditoria A1–A6 e Origin (DNS rebinding + portas implícitas) no binário distribuível. Confirmar que nenhuma ferramenta de fixture aparece no catálogo.
- [ ] Verificar as provas de HTTPS/TLS em processo descartável, identidade OAuth, extração de subject, decisão Broker, revogação e erros fail closed.
- [ ] Analisar em ambiente **isolado** a configuração de destino para introspecção HTTPS, CA, hostname, cadeia TLS, migração de configuração antiga, backup e rollback. Não fazer rollout sem permissão.
- [ ] Registrar as exceções propostas e sua justificativa normativa, sem modificar resultados originais; revisão por pessoa independente do implementador, com decisão assinada e riscos residuais.
- [ ] Validar depois no ChatGPT Web/Android e Central com operador real (issue #65, gate separado). Não afirmar que o teste sintético prova o cliente real.

**GATE C = BLOCKED**, inclusive se a CI do candidato ficar integralmente verde, enquanto houver controles `PARTIAL`, `NOT_PROVEN`, `REAL_ENV_PENDING` relevantes, e até existir parecer normativo independente e critério formal de não aplicabilidade. Gate E (usuário real), licença/assinatura/promoção seguem independentes.

Referências normativas: [protocolo básico](https://modelcontextprotocol.io/specification/2026-07-28/basic); [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http); [OAuth](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); [ferramentas](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [cenários oficiais fixados](https://github.com/modelcontextprotocol/conformance/blob/c37eec888e1c6ff140af79987a40008548b7cc5f/requirements/2026-07-28.yaml).
