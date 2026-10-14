# Congelamento técnico pré-VPS | Pórtico Community | 14/10/2026

> Estado deste documento: **PLANO DE CONGELAMENTO**, não aprovação para
> manutenção em produção. O E2E destrutivo permanece suspenso pela Issue #189.

## Escopo desta rodada

Concluir **uma vez** o pacote de código e ensaios necessários para
homologar a Central de Autorizações HTTPS na instalação existente, sem
reiniciar nem desinstalar a VPS durante revisão. A Community usa
`PORTICO_APPROVAL_SURFACE=external` por padrão; o chat solicita,
o operador autentica-se em outra aba, o Broker decide e a IA consulta
o resultado. MCP Apps/elicitation continuam **opcionais** e não são
pré-requisito. Não transformar o consentimento do ChatGPT para chamar
uma ferramenta em concessão de acesso a pasta.

**Base já promovida e auditada:** `main` SHA
`42a1bbe29660edf61e737fc882e7c126ebc10de3` (PR #188).
**Única candidata ativa para o gate de diagnóstico:** PR #190 / Issue #189.
O SHA definitivo será escrito na Issue #189 após CI + revisão independente
e merge, não antecipado num documento que sofreria novas alterações.

## Matriz de testes exigida NO MESMO HEAD da PR #190

| Gate | Prova exigida | Estado |
| --- | --- | --- |
| CI geral | `reference-implementation-ci`, testes Python de diagnóstico e Go | PENDENTE DE REVALIDAR HEAD FINAL |
| Central HTTPS e segurança | `operator-portal-tests` (testes de API, IPC, Docker/Compose e JS) | PENDENTE |
| UI, sessão e negação | `Adaptive authorization browser harness` (Chromium desktop + mobile, casos adversariais) | PENDENTE |
| OAuth/ZITADEL integrado | `integrated-auth-component-acceptance` | PENDENTE DE REVALIDAR HEAD FINAL |
| Fluxos host sem regressão | `three-vps-simultaneous-acceptance` e `full-ephemeral-acceptance` | PENDENTE DE REVALIDAR HEAD FINAL |
| Ciclo de vida | `lifecycle-acceptance` e `docker-package-acceptance` | PENDENTE DE REVALIDAR HEAD FINAL |
| Diagnóstico fail-closed | Gateway ausente, URL inválida, portal parado, identidades/tokens divergentes, duplicidade Compose, Docker com erro, sigilo e no-op | PENDENTE DE REVALIDAR HEAD FINAL |
| Parecer | **Uma revisão independente** do SHA exato após fechar todas as implementações, com classificação explícita | PENDENTE |

Se alguma prova falhar, corrigir **na mesma PR #190**, repetir a matriz
no novo HEAD e submeter somente o resultado consolidado à revisão final.
**Não criar uma PR por achado nem abrir auditorias parciais repetidas.**
Bloqueios reais e verificáveis entram numa tabela única de pendências,
não em novos ciclos de escopo.

## Tratamento das outras 23 PRs abertas

Existem PRs históricas abertas. **Não integrá-las por atacado**: muitas
representam alternativas, dependem de branches antigas ou cobrem outras
etapas de release. Cada uma deve ser comparada à `main` antes de ser
declarada redundante ou fechada. A triagem abaixo impede confundir
"PR aberta" com "bloqueio desta homologação":

- **Candidatas a sobreposição com o E2E2 já mesclado:** #163, #174,
  #175, #176, #178, #179, #180, #181, #182 e #183. Não mesclar na
  instalação ativa sem comprovar diferença contra `main`.
- **Trabalhos anteriores de UX e documentação:** #85, #160, #164,
  #168, #169, #170 e #171. Regressões de primeiro login e mensagens
  permanecem nas Issues #161/#162, mas não autorizam ampliar o escopo
  da Central antes do teste.
- **Trabalhos arquiteturais/versão/segurança alternativos:** #90, #91,
  #93, #98, #100 e #101. Avaliar na futura organização do roadmap e
  da release assinada, **não** como merge automático desta candidata.

Manter esses PRs identificados no tracker; fechar como substituídos
somente após confirmação de diff/proveniência e registro do motivo.
A existência deles **não exige 23 auditorias novas** para habilitar
o portal já implementado.

## Critério objetivo para declarar CÓDIGO CONGELADO

1. GitHub registra todos os workflows exigidos com `success` **no HEAD
   exato da #190**, sem jobs pendentes, cancelados ou skipped
   injustificados. Logs críticos são citados na Issue #189.
2. Revisor independente emite parecer favorável sobre o SHA final,
   sem P0/P1 aberto relativo ao diagnóstico ou segurança do portal.
3. Merge da #190 à `main` fixando o SHA revisado e sem bypass da
   proteção da branch; verificar CI pós-merge na `main`.
4. Issue #189 registra SHA completo do merge, referência dos testes,
   inventário **somente não sensível** do protocolo, e decisão
   **CÓDIGO CONGELADO PARA HOMOLOGAÇÃO DA CENTRAL**.
5. Após esse marco, **nenhum commit/PR novo por simples polimento**.
   Somente defeito concreto reproduzido, falha de segurança ou mudança
   expressamente autorizada reabre o freeze.

## Operação posterior, sem confundir gates

Após congelar código, testar com operador a VPS **já instalada**:
diagnóstico read-only e sem exposição do `.env`, estado Docker e router
HTTPS, backup consistente validado, proposta de configuração seletiva
com rollback, autorização específica antes de mudanças, ativação do
portal e teste ChatGPT Android/web de **negar → aprovar somente read →
consultar status → expirar/revogar** numa pasta sintética descartável.

Só quando esse fluxo for aceito e registrado na #189, retomar a
Issue #167: inventário, desinstalação inicial supervisionada,
instalação limpa, OAuth, permissões, segunda desinstalação,
auditoria diferencial e preservação de terceiros.

**Gate de código ≠ aceite operacional ≠ release assinada.**
