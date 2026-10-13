# Pacote supervisionado de desinstalação do Pórtico Community

> **Estado: candidato em validação efêmera. Não aplicar à VPS de produção
> antes da aprovação da PR e confirmação expressa do operador.**

Este pacote é destinado à instalação Community de projeto Compose
`mcp-vps-agent`, executada a partir do checkout original da própria
instalação. Ele **não** remove outros projetos Docker, sites, bancos de
terceiros, dados mantidos sob `/opt`, nem o Traefik compartilhado.

## Conteúdo e proveniência

O artefato de CI `portico-uninstall-candidate` contém:

- `portico-uninstall-candidate.tar.gz`: script `scripts/remove.sh` aprovado
  na PR (não inclui `.env` ou credenciais);
- `portico-uninstall-candidate.tar.gz.sha256`: digest para conferir os bytes.

Na CI de pull requests, `SOURCE_COMMIT` representa o **merge temporário testado**
(`GITHUB_SHA`). O campo `PR_HEAD_SHA` aponta para o commit durável da branch,
e `PR_BASE_SHA` para a base; `SOURCE_SCRIPT_SHA256` identifica os bytes do script.
Todos devem ser conferidos. Não atribuir o merge temporário à revisão da branch.
Para uso real, reconstruir o pacote depois da promoção aprovada à `main`.

A revisão deve fixar ambos os SHAs e verificar os logs do
workflow `uninstall-package-e2e` que gerou o artefato. **Uma PR draft não é
autorização de execução ou de merge.**

## Procedimento planejado com o proprietário

1. Confirmar que a instalação ativa pertence ao checkout original e que há
   backup **fora** do checkout do estado, da policy e da identidade OAuth.
   A desinstalação em modo purge apaga arquivos/volumes de identidade.
2. Fazer download do artefato do workflow aprovado, comparar o SHA do commit
   no GitHub e conferir `sha256sum -c`. Não executar scripts vindos de URLs
   mutáveis ou de arquivos não verificados.
3. Extrair em pasta temporária de propriedade do operador. Conferir a lista
   de arquivos do tar antes de copiar. Instalar somente o `scripts/remove.sh`
   verificado no checkout, preservando cópia local do script anterior.
4. Executar primeiro `bash scripts/remove.sh --purge --dry-run`. Revisar
   todas as instâncias, redes/volumes e caminhos exibidos.
5. **Somente após a revisão humana**, iniciar purge com a confirmação
   `PURGE` solicitada pelo script. Não usar `--remove-source` nessa
   primeira etapa: preservamos código e logs para diagnósticos.
6. Auditar contêineres, volumes e redes rotulados pelo Compose. Conferir
   que `traefik-public`, os aplicativos de terceiros e seus dados não foram
   afetados. Se restar recurso ambíguo, **parar** sem prune global ou
   remoções por aproximação.
7. Conservar o backup até que o próximo E2E de reinstalação e OAuth conclua.

### Contratos de autorização destrutiva e remoção segura

- A confirmação de `--purge` deve ser digitada no prompt, ou fornecida
  explicitamente no ambiente do **processo invocador** por operador autorizado.
  Uma chave `VPS_AGENT_PURGE_CONFIRM=PURGE` presente **somente no `.env` não vale**.
- `--remove-source` exige segunda confirmação independente
  (`VPS_AGENT_REMOVE_SOURCE_CONFIRM=REMOVE_SOURCE` no processo invocador ou
  entrada digitada). Valores existentes apenas no `.env` são ignorados.
- `safe` preserva o banco de delegações. Sem Broker/contêineres disponíveis
  para confirmar a revogação, e com `.env` ou `state/` presentes, a operação
  **interrompe com REMOVE BLOCKED antes de mutar dados**. Recuperar o Broker
  para revogação supervisionada, ou executar processo separado de diagnóstico.
- Não contornar um STOP colocando tokens de confirmação no `.env`.

**Não executar** `docker system prune`, `docker volume prune`,
`docker network prune`, `docker compose down` em outros projetos, ou
`rm -rf /opt`.

## Escopo dos testes obrigatórios

- prévia `--dry-run` sem mutação;
- perfis opcionais, incluindo `operator-portal`;
- projeto desconhecido/working_dir diferente bloqueado;
- volumes próprios e `operator-run` removidos;
- redes externas e Traefik preservados;
- falhas parciais não confundidas com sucesso;
- purge repetido sem atingir outro projeto;
- runner Linux descartável com Docker Compose real e um `operator-portal`
  simulado;
- revisão humana final antes da operação na VPS real.

Issues: [#154](https://github.com/josemirmoura/mcp-vps-agent-gateway/issues/154)
e [#153](https://github.com/josemirmoura/mcp-vps-agent-gateway/issues/153).
