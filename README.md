# Laboratório mTLS: Android + Python

Um projeto para estudar autenticação TLS mútua: um app Android apresenta um certificado
de cliente e um servidor Python exige que esse certificado tenha sido emitido pela CA
do laboratório. O app também verifica o certificado e o nome do servidor.

O servidor usa apenas a biblioteca padrão do Python e o OpenSSL instalado no sistema.
O app usa Java, `HttpsURLConnection` e o `KeyChain` do Android.

## Estrutura

```text
android-mtls-lab/
├── README.md
├── .gitignore
├── server/
│   ├── lab.py                 # Certificados, servidor e testes locais
│   └── .venv/                 # Ambiente Python local; ignorado pelo Git
├── android/
│   ├── gradlew                # Gradle Wrapper: versão fixa e checksum
│   ├── gradle/wrapper/
│   └── app/src/
│       ├── main/              # Activity, manifesto e configuração básica de TLS
│       └── debug/             # Confiança na CA somente para depuração
├── scripts/
│   ├── prepare.sh             # Gera credenciais e prepara o app
│   ├── build-android.sh       # Prepara e compila o APK
│   └── run-server.sh          # Executa o servidor e grava sua saída
└── .local/                    # Gerada localmente; ignorada pelo Git
```

Para estudar tudo no VS Code, abra a pasta raiz: `code .`.
Para compilar ou depurar o app no Android Studio, abra a subpasta `android/`.

## O que acontece em uma conexão

```mermaid
sequenceDiagram
    participant A as App Android
    participant S as Servidor Python
    A->>S: Conecta por TLS (localhost:8443 via ADB)
    S-->>A: Certificado do servidor e pedido de certificado de cliente
    Note over A: Verifica a CA, a validade e o nome localhost
    A->>S: Certificado do cliente e prova de posse da chave privada
    Note over S: Verifica o certificado do cliente contra a CA do laboratório
    Note over A,S: Com a negociação TLS concluída, trafega o HTTP
    A->>S: GET /
    S-->>A: HTTP 200 + identidade autenticada
```

Este desenho resume o fluxo; não representa todas as mensagens do protocolo.
A chave privada não é enviada ao servidor. O certificado contém a chave pública,
e a negociação TLS comprova a posse da chave privada correspondente.

Há duas configurações independentes no Android: **em quais servidores confiar** e
**qual identidade apresentar como cliente**. A primeira está no XML de segurança;
a segunda usa o `KeyChain`. A [documentação do Android sobre confiança em certificados](https://developer.android.com/privacy-and-security/security-config)
e a [referência de KeyChain](https://developer.android.com/reference/android/security/KeyChain)
explicam essas duas partes.

mTLS autentica a identidade. Decidir o que essa identidade pode fazer é uma etapa de
autorização da aplicação. Este servidor didático aceita qualquer certificado de
cliente válido emitido pela sua CA e devolve o CN; não implementa regras de permissão
por usuário.

## Pré-requisitos

Os comandos abaixo são para um terminal Bash no Linux, executados na raiz do projeto.

| Componente | Configuração deste projeto |
|---|---|
| Python e OpenSSL | Python 3 e OpenSSL 3; sem dependências pip; validado com Python 3.13 |
| Java | JDK 17 ou 21; validado com JDK 21 |
| Gradle | 8.11.1, fornecido pelo Wrapper |
| Android Gradle Plugin | 8.9.2 |
| SDK Android | Platform 35, Build-Tools 35.0.0 e Platform-Tools (`adb`) |
| Aparelho | Android 8.0 / API 26 ou superior, depuração USB autorizada |

Defina `JAVA_HOME` para o JDK e `ANDROID_HOME` para o SDK da sua máquina, com `java`,
`keytool` e `adb` no `PATH`. O Android Studio pode registrar o caminho do SDK em
`android/local.properties`, arquivo que fica fora do Git. Se estiver usando a linha
de comando do SDK, instale os componentes com:

```bash
sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0"
sdkmanager --licenses
```

A primeira compilação precisa de internet para obter o Gradle e as dependências.
As versões foram fixadas conforme a [compatibilidade do AGP 8.9](https://developer.android.com/build/releases/agp-8-9-0-release-notes).

## Ambiente virtual Python

Na raiz do projeto, crie o ambiente dentro de `server/` e ative-o:

```bash
python3 -m venv server/.venv
source server/.venv/bin/activate
python --version
```

No Debian, se o primeiro comando informar que `ensurepip` não está disponível,
instale `python3-venv` com o gerenciador de pacotes e repita a criação do ambiente.

O servidor não precisa de pacotes adicionais do pip: usa a biblioteca padrão do Python
e chama o executável `openssl` do sistema. Em novos terminais, basta repetir o comando
`source server/.venv/bin/activate`. Para sair do ambiente, execute `deactivate`.

Se já estiver na pasta `server/`, use `source .venv/bin/activate` e inicie com
`python lab.py serve`. Nesse caso, os logs aparecem no terminal. Para também gravá-los
em `.local/server.log`, use `../scripts/run-server.sh`.

O script `scripts/run-server.sh` usa diretamente `server/.venv/bin/python`, mesmo sem
ativar o ambiente no terminal. A pasta `.venv/` é ignorada pelo Git; depois de clonar
ou mover o projeto para outra máquina, recrie o ambiente com o comando acima.

## 1. Entender o mTLS sem o celular

```bash
python3 server/lab.py test
```

O comando gera credenciais locais se necessário, abre um servidor numa porta
temporária, faz cinco testes TLS reais e encerra esse servidor ao terminar.
Ele não ocupa a porta 8443 do servidor usado pelo app.

| Cenário | Resultado esperado |
|---|---|
| Certificado válido do cliente | HTTP 200 |
| Cliente sem certificado | Recusado pelo servidor |
| Cliente com certificado de outra CA | Recusado pelo servidor |
| Cliente não confia na CA do servidor | Recusado pelo cliente |
| Nome do endereço não corresponde ao certificado | Recusado pelo cliente |

## 2. Preparar e compilar o Android

```bash
./scripts/build-android.sh
```

Esse script gera as credenciais quando ausentes, copia **somente a CA pública** para
os recursos de depuração e compila o app. O APK fica em:

```text
android/app/build/outputs/apk/debug/app-debug.apk
```

Se preferir compilar pela IDE, execute `./scripts/prepare.sh` primeiro e abra
`android/` no Android Studio. Use JDK 17 ou 21 na configuração **Gradle JDK**.
O Java que executa a IDE pode ter outra versão; não precisa ser o Java do Gradle.

Os scripts preservam as credenciais existentes. O APK contém a CA pública do servidor;
o certificado e a chave privada do cliente serão importados separadamente no celular.

## 3. Iniciar o servidor

Em um terminal, execute e deixe aberto:

```bash
./scripts/run-server.sh
```

Ele escuta apenas em `127.0.0.1:8443`. Use `Ctrl+C` para encerrá-lo.
Se já existir um servidor nessa porta, reutilize-o somente se ele usa as mesmas
credenciais, ou encerre essa instância antes de iniciar outra.

O script mostra a saída na tela e a acrescenta a `.local/server.log`. Em outro terminal:

```bash
tail -n 50 -f .local/server.log
```

Cada linha inclui data, hora e fuso, nível e evento. `Ctrl+C` no `tail` encerra apenas
a visualização do log; o servidor continua rodando no outro terminal.

| Evento | O que aconteceu |
|---|---|
| `SERVIDOR_INICIADO` | A porta está aberta e o servidor exige certificado de cliente |
| `TCP_ACEITO` | Uma conexão de rede chegou; a identidade ainda não foi validada |
| `TLS_OK` | O TLS terminou com sucesso; mostra a identidade do cliente, versão e cifra |
| `HTTP_RESPOSTA` | Uma requisição HTTP chegou depois do TLS; mostra método, caminho e status |
| `TLS_RECUSADO` | A negociação TLS falhou; o campo `motivo` explica o erro |
| `CONEXAO_FALHOU` | Houve timeout ou outro problema de conexão; sozinho, isso não comprova uma recusa de certificado |
| `HTTP_EVENTO` | O servidor HTTP registrou um erro de processamento |

Com o Xiaomi conectado e `adb reverse tcp:8443 tcp:8443` configurado, faça esta prática:

1. Abra o log com `tail -n 50 -f .local/server.log`.
2. Toque em **Testar sem certificado**. Espere `TCP_ACEITO` e `TLS_RECUSADO`, com
   `PEER_DID_NOT_RETURN_A_CERTIFICATE`. Não há resposta HTTP: o bloqueio ocorre antes.
3. Escolha a identidade e toque em **Testar mTLS**. Espere `TCP_ACEITO`, `TLS_OK`
   com `cliente='android-lab'` e `HTTP_RESPOSTA` com `status=200`.

Exemplo abreviado de sucesso (o arquivo também mostra o horário e a porta de origem):

```text
INFO TCP_ACEITO origem=127.0.0.1:...
INFO TLS_OK ... cliente='android-lab' protocolo=TLSv1.3 ...
INFO HTTP_RESPOSTA ... metodo=GET caminho='/' status=200
```

As linhas da mesma conexão têm a mesma `origem=IP:porta`. Pelo encaminhamento USB,
o servidor vê a conexão local do ADB (`127.0.0.1`), não o IP Wi-Fi do Xiaomi.
Não são registrados chaves privadas, senhas, corpos ou cabeçalhos HTTP; o caminho
registrado também omite a query string. Os logs não são uma captura das mensagens
TLS: mostram os eventos observados pelo servidor após descriptografar a conexão.

## 4. Instalar e conectar o celular

Conecte apenas o aparelho de teste, habilite a depuração USB e aceite a autorização
exibida nele. Em uma VM, direcione o dispositivo USB para o sistema convidado.

```bash
adb devices -l
```

O estado deve ser `device`. Em seguida:

```bash
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
adb push .local/certs/client.p12 /sdcard/Download/mtls-client.p12
adb reverse tcp:8443 tcp:8443
adb reverse --list
```

O `adb reverse` liga a porta 8443 do celular à porta 8443 da máquina que executa o ADB.
Assim, `https://localhost:8443` no app chega ao servidor no Debian. Refaça esse
encaminhamento após desconectar o USB. Com mais de um aparelho, use `adb -s SERIAL ...`.

Abra **Laboratório mTLS** no celular:

1. Toque em **Importar certificado (.p12)** e selecione `mtls-client.p12` em Downloads.
2. Conclua a importação na interface do Android com a senha **`lab-android`**.
3. Toque em **Escolher identidade** e selecione `android-lab`.
4. Compare **Testar sem certificado**, que deve falhar, com **Testar mTLS**, que deve
   responder HTTP 200.

O Android pode exigir um bloqueio de tela para armazenar a credencial.
Se a tela pedir o PIN/senha de desbloqueio do aparelho, use a credencial do próprio
celular; `lab-android` é a senha do arquivo `.p12`.
Uma resposta válida tem este formato; a versão do TLS depende da negociação:

```json
{"mtls": true, "cliente": "android-lab", "tls": "TLSv1.3"}
```

### Se a importação disser “senha incorreta”

No Redmi Note 8 com Android 10, o importador pode mostrar essa mensagem quando não
consegue ler o formato PBES2/PBKDF2 usado por padrão pelo OpenSSL 3, mesmo com a senha
correta. O log do aparelho identifica essa situação como `SecretKeyFactory not available`.

Este projeto exporta o `.p12` com PBE-SHA1-3DES e MAC SHA-1, compatíveis com o importador
antigo. Essas opções protegem apenas o arquivo de transporte do laboratório; os
certificados continuam assinados com SHA-256 e o servidor continua usando TLS 1.2 ou
superior. Veja as [opções de exportação PKCS12 do OpenSSL](https://docs.openssl.org/3.5/man1/openssl-pkcs12/).

Se você gerou o arquivo com uma versão anterior do projeto, reexporte a identidade
existente e envie novamente ao aparelho:

```bash
python3 server/lab.py export-client
adb push .local/certs/client.p12 /sdcard/Download/mtls-client.p12
```

Cancele a tentativa de importação que já estiver aberta. No app, toque novamente em
**Importar certificado (.p12)**, selecione o arquivo atualizado e digite `lab-android`.
O instalador pode manter os bytes antigos em memória até o arquivo ser selecionado
outra vez. Essa reexportação preserva as chaves, os certificados e suas validades;
não exige recompilar o APK nem reiniciar o servidor.

Para confirmar a senha e inspecionar o formato no Debian, sem exibir a chave privada:

```bash
openssl pkcs12 -in .local/certs/client.p12 -info -noout -passin pass:lab-android
```

## 5. Fazer a mesma chamada pelo terminal

Com o servidor rodando, execute na raiz do projeto:

```bash
curl --noproxy '*' \
  --cacert .local/certs/ca.crt \
  --cert .local/certs/client.crt \
  --key .local/certs/client.key \
  https://localhost:8443/
```

Repita sem `--cert` e `--key`: a conexão deve ser recusada. Mantenha `--cacert`;
usar `-k` removeria a verificação do servidor que queremos estudar.

## Roteiro de leitura do código

| Arquivo / trecho | O que observar |
|---|---|
| [server/lab.py](server/lab.py) → `generate()` | CA, certificados com usos `serverAuth` e `clientAuth`, SAN `localhost` e PKCS12 |
| `renew()` e `issue_certificates()` | Renovação das identidades, preservando as CAs e as chaves |
| `server_context()` | Certificado do servidor, CA aceita para clientes e `ssl.CERT_REQUIRED` |
| `Server.get_request()` | Negociação TLS antes de qualquer processamento HTTP |
| `Handler.do_GET()` | Certificado já autenticado e resposta JSON |
| `client_context()` e `test()` | Experimentos positivos e negativos com TLS real |
| [MainActivity.java](android/app/src/main/java/lab/mtls/MainActivity.java) → `onActivityResult()` | Importação do `.p12` pela interface de credenciais do sistema |
| `test()` e `ClientIdentity` | Seleção da chave pelo `KeyChain` e uso de `X509ExtendedKeyManager` |
| [Configuração de depuração](android/app/src/debug/res/xml/network_security_config.xml) | CA do laboratório confiável apenas no app de depuração |

O app mantém a verificação padrão de hostname e o TrustManager padrão. Não há um
TrustManager que aceite qualquer certificado. O servidor usa `ssl.CERT_REQUIRED`
para exigir o certificado do cliente; veja também a [referência de TLS do Python](https://docs.python.org/3/library/ssl.html).

## Credenciais e arquivos gerados

Cada clone novo gera sua própria CA. `.local/certs/client.p12` contém a identidade
privada do cliente; sua senha `lab-android` é pública e serve apenas ao exercício.
As chaves PEM locais não têm senha. A CA dura 30 dias e os certificados de servidor
e cliente duram 7 dias. A chave de assinatura do APK é de depuração.

### Renovar certificados expirados, mantendo a CA

Se aparecer `CERTIFICATE_VERIFY_FAILED: certificate has expired`, confira a validade:

```bash
openssl x509 -in .local/certs/server.crt -noout -dates
openssl x509 -in .local/certs/client.crt -noout -dates
```

O campo `notAfter` indica a expiração em GMT/UTC. O ambiente virtual Python não altera
essa data. Enquanto as CAs ainda tiverem mais de sete dias de validade, pare o servidor
e execute, na raiz do projeto:

```bash
server/.venv/bin/python server/lab.py renew
server/.venv/bin/python server/lab.py test
```

Se estiver dentro de `server/` com o ambiente ativado, os comandos são `python lab.py renew`
e `python lab.py test`. A renovação emite novos certificados de servidor e clientes por
sete dias, preserva as CAs e as chaves privadas e reexporta o `.p12` compatível com Android.
O estado anterior fica salvo em `.local/certs-before-renew-<data>/`, fora do Git.

Inicie novamente o servidor com `./scripts/run-server.sh`. Para testar no Xiaomi,
atualize a identidade instalada, pois o Android ainda guarda o certificado antigo:

```bash
adb push .local/certs/client.p12 /sdcard/Download/mtls-client.p12
```

No app, importe o arquivo atualizado usando `lab-android` e escolha essa identidade
novamente. Se o Android pedir confirmação para substituir a identidade anterior,
confirme a substituição. A CA continua a mesma, portanto o APK não precisa ser recompilado.
A validação dos certificados permanece ativa.

### Criar uma nova CA

Se a CA também expirou ou tem menos de sete dias restantes, pare o servidor e gere um
novo laboratório. Este comando mantém a chave de assinatura do app:

```bash
mv .local/certs ".local/certs-anteriores-$(date +%Y%m%d-%H%M%S)"
./scripts/build-android.sh
```

Depois reinicie o servidor, reinstale o APK, transfira o novo `.p12`, importe-o e
selecione a nova identidade. Uma CA nova não funciona com o APK ou a identidade antigos.

Este é um laboratório local: a renovação é manual. Ele não implementa gestão de usuários,
revogação de certificados, rotação automática ou operação de um serviço público.

## Problemas comuns

| Sintoma | O que conferir |
|---|---|
| `unauthorized` no ADB | Desbloqueie o aparelho e aceite a depuração USB |
| “Senha incorreta” ao importar `.p12` | Confira se a tela pede a senha do arquivo ou o PIN do aparelho; para arquivos antigos, siga a seção de reexportação acima |
| `Connection refused` ou timeout | Servidor iniciado e `adb reverse --list`; erro de rede não prova recusa do certificado |
| Falha de certificado mesmo com identidade selecionada | CA do APK, certificado do servidor e `.p12` devem pertencer ao mesmo laboratório; confira validade e relógio |
| `certificate has expired` | Renove com `python lab.py renew` dentro de `server/`, reinicie o servidor e importe o novo `.p12` no Android |
| `Address already in use` | Outra instância ocupa 8443; identifique-a com `ss -ltnp '( sport = :8443 )'` |
| `SDK location not found` | Ajuste `ANDROID_HOME` ou o SDK em `android/local.properties` |
| Erro de Java no Gradle | Confira `java -version`, `JAVA_HOME` e o Gradle JDK da IDE |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | Um app com o mesmo ID foi assinado com outra chave. Preserve a chave original ou desinstale o app anterior, ciente de que isso apaga seus dados |

## Publicar no GitHub

O `.gitignore` exclui `.local/`, credenciais, APKs, caches, configurações da máquina e
arquivos de compilação. O código, os scripts e o Gradle Wrapper devem ser versionados.
Confira os arquivos que entrarão no primeiro commit:

```bash
git init -b main
git add .
git diff --cached --stat
git diff --cached
git commit -m "Adiciona laboratório mTLS para Android e Python"
```

Se o Git pedir sua identidade, configure `user.name` e `user.email` com os valores
que deseja associar aos commits. Crie um repositório vazio no GitHub e substitua
`SEU_USUARIO` pela sua conta:

```bash
git remote add origin https://github.com/SEU_USUARIO/android-mtls-lab.git
git push -u origin main
```

Os comandos de publicação exigem a sua autenticação no GitHub. Compartilhe os arquivos
versionados; um ZIP manual de toda a pasta pode incluir `.local/`, pois o `.gitignore`
é respeitado pelo Git, não por compactadores comuns.
