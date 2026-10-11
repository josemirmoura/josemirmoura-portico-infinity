# Gate C: ensaio seguro de migracao HTTPS/OAuth e rollback

**Status:** roteiro tecnico, nao evidencia de implantacao real nem autorizacao de deploy.

## Provas obtidas em laboratorio

- tests/scripts/test_prepare_https_introspection.py: Docker simulado em pasta descartavel; verifica --check sem escrita, migracao --apply, backup 0600, rejeicao de resposta inesperada e restauracao da configuracao original.
- tests/integration/mcp_https_oauth_broker_contract_test.go: TLS validado com certificado confiavel em laboratorio, introspeccao OAuth, HTTP 401/403, MCP, Broker via Unix socket e politica Scoped.
- CI de pacote: testes de instalacao, lifecycle e rollback em runner descartavel.

**Limite:** os testes nao certificam o DNS real, Traefik, CA, ZITADEL em producao, versao RC7 instalada nem recuperacao dos volumes reais.

## Ensaio exigido antes de fechar o P1

1. Obter aprovacao operacional e escolher um clone verdadeiramente isolado, com credenciais e dados sinteticos. Nao reusar volumes, sockets, portas nem certificados sensiveis da producao.
2. Congelar SHA e validar a publicacao imutavel e assinada. Branch de staging nao e release; nunca contornar os validadores do updater.
3. Construir uma topologia Docker/Traefik representativa, com hostname confiavel acessivel a partir da rede do Gateway e introspeccao HTTPS certificada sem insecure e sem redirects.
4. Verificar a configuracao Compose sem imprimir segredos. Executar scripts/prepare-https-introspection.sh --check no clone; comprovar que nao modificou o arquivo de configuracao.
5. Somente no clone aprovado, executar scripts/prepare-https-introspection.sh --apply; verificar URL HTTPS, backup 0600 e nenhuma reinicializacao surpresa.
6. Com um candidato de release assinado e publicado, ensaiar scripts/update.sh pelo caminho suportado; comprovar MCP, 401 sem token, 403 por escopo insuficiente, autorizacao correta no Broker e auditoria.
7. Injetar falha depois do snapshot no clone e ensaiar rollback. Exigir integridade de estado, cadeia de auditoria valida e nenhuma concessao ou delegacao revogada ressuscitada.
8. Produzir evidencia saneada com SHA, digests, versoes antes/depois, certificados verificados, passos PASS/FAIL e recuperacao. Nao compartilhar .env, senha, token, private key ou logs autenticos.

## Regras de bloqueio

Gate C continua BLOQUEADO se TLS exigir bypass de certificado, update demandar commit arbitrario nao publicado, a migracao perder backup, houver exposicao de credenciais, o rollback ampliar autoridade ou faltarem evidencias da topologia real.

Este roteiro nao deve ser usado para iniciar testes no host de producao sem autorizacao explicita. Mesmo --check inicia um container e efetua comunicacao de rede.
Parecer normativo independente e aceite real com ChatGPT sao gates separados.
