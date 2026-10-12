# Pórtico Gate C lab isolado (11/10/2026)

Esta pasta foi criada após autorização temporária e é um ensaio isolado de infraestrutura, não um deploy de produção.

Guardrails: não há publicação de portas, Docker socket, mounts de /opt externos, volumes externos, network host ou conexões com banco/secret de produção. O projeto Compose tem nome exclusivo e rede internal=true. OAuth é um stub sintético e certificados são efêmeros (1 dia), sem credenciais reais.

Ensaios: HTTPS do Traefik em rede Docker privada, CA válida injetada no cliente, correspondência de hostname, resposta introspection active=false, credenciais inválidas 401, CA não confiável e hostname incorreto falhando fechados.

Limites: isto NÃO simula ZITADEL real nem valida atualização de rc.7 para release assinada, rollback de volumes reais, autorização do operador real, ou aceita Gate C sozinho. Serviços de produção não devem ser reiniciados ou alterados.
