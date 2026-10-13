# Protocolo de recuperação | MkdirAll e desinstalação

## Falha de propriedade ao criar diretórios (Issue #186)

Quando o Broker cria uma subpasta em uma raiz autorizada, seu UID/GID
deve ser herdado da pasta pai verificada. Uma falha de `fchown` **nunca**
pode ser apresentada como sucesso.

A rotina `MkdirAll` tenta desfazer somente o diretório vazio e de mesmo
inode que acabou de criar. Se ele estiver ocupado, tiver sido trocado ou
não puder ser removido sem risco, a operação retorna um erro contendo:

- o caminho físico do diretório criado;
- a indicação `MANUAL RECOVERY required`;
- o erro original de mudança de proprietário.

Não remover recursivamente esse caminho por automatismo. Inspecionar
`stat -c '%u:%g %a %n' -- '<caminho informado>'` e
`ls -la -- '<caminho informado>'` antes de qualquer mudança. Conferir o
caminho real, proprietário, conteúdo, a autorização e a existência de
dados de terceiros. Qualquer correção deve ser feita por operador humano,
na raiz explicitamente autorizada e após backup quando houver dados.

A suíte privilegiada `TestMkdirAllChownFailure*` testa falha induzida,
desfazimento de pasta vazia, aviso de resíduo ocupado, nova tentativa
controlada e preservação de caminhos fora de escopo.

## Leitura do arquivo .env (Issue #187)

O desinstalador **não executa** o arquivo `.env` como shell. Ele abre
arquivo regular com `O_NOFOLLOW`, tamanho máximo de 256 KiB, valida
entradas UTF-8 `KEY=VALUE` e só exporta para o processo as variáveis
utilizadas no desinstalador. Variáveis de confirmação de `--purge` e
`--remove-source` nunca são obtidas desse arquivo.

Valores com aspas simples/duplas e UTF-8 são aceitos; comandos,
interpolações com cifrão, crases, ponto e vírgula, pipes e redirecionamentos
são recusados como inválidos sem imprimir credenciais. O Compose continua
lendo seu `.env` em separado. Se valores especiais do ambiente real
não satisfizerem o formato seguro, a operação deve **parar**; não
desabilitar essa verificação para acelerar o E2E.

## Gate operacional

Mesmo que a CI e a reauditoria aprovem ambas as issues, o purge real
exige: identificar checkout e proprietário, conferir hash do script e
do pacote operacional da `main`, backup fora do checkout, prévia
`--dry-run`, revisão do inventário Docker e autorização explícita
no terminal. Nenhum comando prune global. O teste completo somente será
aceito após a segunda desinstalação e verificação dos serviços terceiros.

Referências: #167, #186, #187 e PR #184.
