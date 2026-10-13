# Reauditoria final | Pórtico Community E2E2

Este documento registra o escopo para auditoria externa do candidato Community.
Não é autorização para publicação, promoção à `main`, remoção nem acesso à VPS.

## Histórico de reprovações e correções mínimas

- PR #177, parecer [reprovado](https://github.com/josemirmoura/mcp-vps-agent-gateway/pull/177#issuecomment-6145789580): B1–B4 corrigidos na PR #181.
- PR #184, parecer [reprovado](https://github.com/josemirmoura/mcp-vps-agent-gateway/pull/184#issuecomment-6147661554): R1 e R2 corrigidos na PR #185.
- PR #178: banner PORTICO com identidade fixa em inglês e instalação pt-BR/en.
- Os pareceres anteriores permanecem verdadeiros para os seus SHAs originais.
  Parecer favorável sobre um commit novo **não** pode ser deduzido dos 16
  workflows verdes.

## Testes de regressão que precisam aparecer nos logs

- B1: `TestAuthorizedRootSwapToSymlinkNeverEscapes`,
  `TestAuthorizedAncestorSwapToSymlinkNeverEscapes`,
  `TestConcurrentAuthorizedRootSwapNeverLeaks`. Reexaminar a aquisição
  de FDs durante renomeações e paths ancestrais.
- B3: `TestOwnerNewDirectoryAndCopyAcrossRoots` e
  `TestAtomicWriteHostOwner` executados como **root**, sem skips;
  examinar eventual diretório criado antes de `Chown` falho.
- B2/R1: `test_safe_no_containers_with_persisted_grants_and_env_stops`,
  `test_safe_no_containers_with_env_even_without_state_stops`,
  `test_safe_no_env_no_containers_but_persisted_grants_stops`,
  cenários de `revoke-all` falho, ausência de credenciais e STOP antes
  de `compose down`.
- B4/R2: `test_purge_confirmation_only_in_env_file_must_not_authorize`
  e `test_remove_source_confirmation_only_in_env_file_must_not_authorize`,
  com tokens exclusivamente no `.env`. Adicionalmente, volume de nome
  coincidente e label estrangeira, bind mount sob `state/backups`,
  symlinks, falha de inventário e repetição em Docker descartável.
- ZITADEL Login V2 v4.19.4, cookie assinado com segredo persistente, DCR,
  OAuth introspecção e HTTPS, autorização MCP, onboarding bilíngue,
  pacote Docker e rollback, artefato de desinstalação com hashes.

## Critérios

1. **Um único HEAD de PR contra `main`** e todos os workflows esperados
   efetivamente executados e aprovados nesse SHA (não usar status de
   branches intermediárias como substituto).
2. Novo parecer independente com classificação APROVADO, APROVADO COM
   RESSALVAS ou REPROVADO, citando SHA, evidência e correções mínimas.
3. Mesmo com aprovação: gerar pacote operacional a partir da `main`
   promovida, inventariar e validar backups externos antes de qualquer
   destruição e obter autorização específica do operador para cada purge.
4. E2E real supervisionado: primeira desinstalação, instalação limpa,
   OAuth/UI humano, permissões/negações/expiração, segunda desinstalação,
   inventário diferencial; somente então avaliar divulgação.

Documentação de execução: `docs/e2e2-full-cycle-acceptance.pt-BR.md`.
