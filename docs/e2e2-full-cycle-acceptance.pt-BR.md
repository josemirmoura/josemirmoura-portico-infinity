# Pórtico Community: aceite do segundo E2E, do zero à desinstalação final

**Situação:** roteiro de homologação. Nenhuma etapa destrutiva autorizada por este documento.
**Escopo:** Community Linux + um cliente MCP compatível, VPS compartilhada com
Traefik e aplicações de terceiros. Cloud comercial, Windows/macOS e Full fora do
aceite. A edição Community utiliza autoridade Scoped, deny-by-default.

## Gate 0: código e pacote testados (sem alteração da VPS)

- [ ] Fixar o SHA exato aprovado da `main` e registrar origem do desinstalador
  (run/artifact GitHub, `SOURCE_COMMIT`, SHA-256 do ZIP e do TAR).
- [ ] Todos os workflows aplicáveis concluídos com sucesso **no mesmo SHA**.
- [ ] Revisão independente de Broker, ownership, symlinks, TOCTOU, OAuth,
  Login V2 e credenciais; registrar ressalvas não resolvidas.
- [ ] Testes descartáveis com Docker real comprovam `--purge --dry-run`,
  `operator-portal`, `operator-run`, limpeza repetida e preservação de edge.
- [ ] Licença, assinatura de release e critérios de divulgação tratados como
  gate separado. Aprovação de CI sozinha não libera publicação.

## Gate 1: inventário e backup na VPS (somente leitura)

- [ ] Registrar `hostname`, Docker/Compose, diretório real do checkout,
  `git rev-parse HEAD`, versão **efetivamente executada** do ZITADEL,
  modo Scoped e auditoria de permissões.
- [ ] Inventariar contêineres, volumes, redes, Traefik, serviços e projetos
  de terceiros. Fotografar/salvar lista de recursos antes/depois.
- [ ] Backup fora da árvore a remover: `.env`, policy, auditoria, journals
  necessários e volumes OAuth/PostgreSQL. Permissões 0700/0600, sem segredos
  em logs/chat; validar integridade e capacidade de restauração.
- [ ] Conferir que backups e dados de terceiros não integram alvos de purge.
- [ ] Examinar riscos do patch de segurança do Login V2; se a VPS utilizar
  versão vulnerável, decidir explicitamente qualquer medida emergencial.

## Gate 2: primeira desinstalação real (supervisionada)

- [ ] Instalar **somente** o script hash-verificado no checkout original,
  preservando a versão anterior e os logs.
- [ ] Executar `bash scripts/remove.sh --purge --dry-run` e conferir a prévia.
- [ ] Aprovação explícita do operador após verificar **cada alvo**.
- [ ] Executar `--purge` com confirmação e **sem** `--remove-source` nesta fase.
- [ ] Confirmar ausência de recursos do projeto, ausência de volumes órfãos,
  serviço MCP offline e manutenção de Traefik, redes externas, sites e volumes
  de terceiros. Bloquear em caso de ownership incerto.
- [ ] Invocação idempotente repetida apenas em condições conhecidas.
- [ ] Nenhum `docker * prune`, exclusão aproximada de `/opt`, ou limpeza global.

## Gate 3: instalação do zero pelo fluxo público

- [ ] Nova instalação a partir do SHA/artefato aprovado; reproduzir escolha de
  idioma, verificações de Docker/Compose e reutilização segura de Traefik.
- [ ] Validar Gateway não-root, Broker local, socket, healthchecks, policy Scoped,
  teto físico /opt e sem acesso inesperado a outras aplicações.
- [ ] Provisionar OAuth integrado com Login V2 corrigido, segredo privado
  persistente e owner único. Simular interrupção no POST e retomar sem duplicar.
- [ ] Validar descoberta OIDC, DCR, PKCE S256, introspecção HTTPS, issuer,
  audience, TLS, bloqueio de tokens inválidos/expirados/revogados.
- [ ] Conferir tutorial multicliente e preenchimento do cadastro MCP no ChatGPT.

## Gate 4: uso operacional e autorizações no ChatGPT

- [ ] Conexão OAuth real no ChatGPT Web; repetir em Android, se aplicável.
  Registrar imagens das telas de login, consentimento e erros de UI, **sem
  capturar credenciais nem tokens**.
- [ ] Distinguir consentimento nativo da chamada da ferramenta de autorização
  de pasta feita pelo operador na Central/CLI.
- [ ] Raiz experimental dentro de /opt: leitura autorizada; escrita inicialmente
  negada; concessão work temporária; criação, leitura e edição; verificar no
  Linux UID/GID do operador e modo 0600 do arquivo.
- [ ] Testar travessia de diretórios, escapes por symlink, paths fora de escopo,
  leitura após revogação e expiração; todos devem retornar negativas rastreáveis.
- [ ] Revogar grants; confirmar `permissions.list_root_access` sem delegações
  dinâmicas. Testar cancelamento/negação sem criar novos grants.
- [ ] Exercitar operações de uso permitidas pela policy (filesystem, shell
  sandboxed, Docker tipado somente se habilitado) e auditoria íntegra.
- [ ] Verificar apresentação de `permission_denied` no cliente, inclusive
  envelope `INVALID_ARGUMENT`, separando possível diferença do host ChatGPT.
- [ ] Conferir saudação do primeiro login e comportamento do botão Voltar no
  ZITADEL; sem prova visual não marcar PASS.

## Gate 5: segunda desinstalação e encerramento

- [ ] Repetir backup/inventário; confirmar não haver grants persistentes.
- [ ] Executar prévia da remoção, nova autorização humana e purge supervisionado.
- [ ] Comprovar ausência de runtime/estado MCP, volumes órfãos, rotas do MCP
  e manutenção intacta de workloads/Traefik/Cloud externos.
- [ ] Registrar idempotência, inventário diferencial, integridade dos serviços
  não envolvidos e resíduos justificados.
- [ ] Consolidar matriz: PASS / FAIL / BLOCKED / NOT_TESTED, timestamp,
  SHA, responsável e evidência por teste. **Não tratar BLOCKED como PASS.**
- [ ] Se FAIL, abrir issue reproduzível com correção mínima e novo ciclo.
  Se tudo PASS e gates independentes de licença/segurança/release completos,
  considerar divulgação controlada da Community.
- [ ] Reativação de instância de serviço após o teste exige decisão operacional
  separada, já que o E2E encerra com a segunda desinstalação.

## Formato mínimo do registro

| Gate | Caso | Esperado | Obtido | Status | Evidência/issue |
| --- | --- | --- | --- | --- | --- |
| 0–5 | ID do teste | Condição verificável | Resultado observado | NOT_TESTED | URL ou log redigido |

**STOP imediato:** divergência de SHA/assinatura, backup não verificado,
grant inesperado, vulnerabilidade sem mitigação, operação fora de escopo,
resultado de teste falso-positivo, perda de dado, alteração de terceiros,
falha de auditoria ou recurso ambiguamente associado ao projeto.

Referências: issues #153, #154, #157, #159, #161, #162, #165, #166, #167, #173;
PRs #172, #174, #175, #176, #177.
