# mTLS Shared Embedded Credential — v0.1

Terceiro laboratório independente deste repositório. Uma identidade cliente é
gerada na VM e embutida no APK como PKCS#12. Cada instalação importa uma cópia no
AndroidKeyStore. O Android autentica o **API Gateway** com CA, hostname e pins
SPKI; o gateway exige o certificado cliente e termina o mTLS externo. Outro
processo Python representa o Spring Boot atrás de uma conexão interna autenticada.

**Build disponível: funcional, sem proteção comercial.**

- **DexGuard: NOT AVAILABLE / NOT VALIDATED. Proteção: NOT ACTIVE.**
- **RASP: NOT ACTIVE / NOT VALIDATED.** Não há simulação de aprovação.
- Android: `lab.mtls.embedded`, nome **mTLS Embedded Credential**.
- Perfil público central: [credential.json](credential.json), geração `embedded-v1`, alias `mtls-embedded-v1`, RSA 2048, certificados finais válidos por 30 dias.

O gateway prova posse da **mesma chave compartilhada**. Ele não distingue Device A
de Device B por essa identidade. Login/MFA e sessão continuam necessários para
acessar dados do usuário. Importar a chave no Keystore não remove a cópia do APK.

Leia também [arquitetura e migração](ARCHITECTURE.md), [ameaças](THREAT_MODEL.md),
[testes executados](VALIDATION.md) e [integração comercial pendente](DEXGUARD.md).

## Estrutura e independência

```text
embedded-credential-lab/
├── README.md / ARCHITECTURE.md / THREAT_MODEL.md / VALIDATION.md / DEXGUARD.md
├── credential.json                 # configuração pública da geração
├── requirements.txt
├── android/                        # app Java e instrumentação separada
├── gateway/                        # termina mTLS externo; política e proxy
├── backend/                        # serviço interno, senha/TOTP/sessão
├── common/                         # PKI, HTTP limitado e administração local
├── scripts/                        # preparação, build, execução e testes
├── tests/                          # conexões TLS reais entre os dois serviços
├── .venv/                          # gerado, ignorado pelo Git
└── .local/                         # gerado, privado, ignorado pelo Git
    ├── embedded/                   # PKI, política, contas e sessões
    ├── generated-assets/mtls/client.p12
    ├── generated-java/             # inclui senha injetada no build
    ├── generated-res/              # CA pública + pins
    ├── debug.keystore
    ├── gateway.log / backend.log
    └── validation/
```

Não depende de imports, dados ou processos dos outros laboratórios. Os dois
laboratórios anteriores mantêm suas pastas e seus próprios comandos.

## Executar nesta VM

Pré-requisitos usados: JDK 21, Android SDK 35, Python 3.13 com `venv`, OpenSSL,
ADB, Gradle wrapper 8.11.1 e Android Gradle Plugin 8.9.2. O app exige Android 8/API
26 ou superior. O primeiro build usa rede para baixar dependências.

Terminal 1:

```bash
source /home/lucas/Documents/Codex/2026-09-17/x20/outputs/mtls-android/env.sh
cd /home/lucas/Documents/Codex/2026-09-17/x20/outputs/android-mtls-lab/embedded-credential-lab
./scripts/build-android.sh
./scripts/run-lab.sh
```

`build-android.sh` prepara `.venv`, PKIs, assets e assinatura de debug e gera
`android/app/build/outputs/apk/debug/app-debug.apk`. Preparações seguintes
preservam a PKI válida: **rebuild não rotaciona a identidade**.
Não existe build release comercial configurada.

`run-lab.sh` verifica as cinco portas antes de iniciar gateway e backend como
processos diferentes, sempre com os diagnósticos habilitados. Se houver conflito,
falha sem matar o processo que ocupa a porta. `Ctrl+C` encerra os seus dois filhos.
Se um serviço falhar, o supervisor encerra o outro e informa a falha.

Terminal 2:

```bash
source /home/lucas/Documents/Codex/2026-09-17/x20/outputs/mtls-android/env.sh
cd /home/lucas/Documents/Codex/2026-09-17/x20/outputs/android-mtls-lab/embedded-credential-lab
adb devices -l
./scripts/connect-phone.sh
```

Se houver vários aparelhos, passe o serial como argumento a `connect-phone.sh`.
O script instala somente `lab.mtls.embedded`, abre o app e cria `adb reverse`
para **8643–8646**. Não encaminha a porta do backend. Na validação de 12/10/2026,
o aparelho disponível era um **Moto G8 Play / Android 10**, não o Xiaomi anterior.

| Porta na VM | Serviço | Acesso e finalidade |
|---|---|---|
| 127.0.0.1:8643 | API Gateway | mTLS externo obrigatório; `/identity`, `/session`, `/account`, `/logout` |
| 127.0.0.1:8644 | Gateway HTTPS | somente `/health`, pin principal; sem dados de usuário |
| 127.0.0.1:8645 | Diagnóstico HTTPS | mesma CA e hostname, chave fora dos pins; Android deve recusar |
| 127.0.0.1:8646 | Diagnóstico HTTPS | chave de backup permitida no pinning |
| 127.0.0.1:8650 | Backend interno | exige certificado de serviço do gateway; sem `adb reverse` |

O gateway representa a borda pública, mas nesta VM também escuta em loopback:
o acesso do celular ocorre pelo túnel ADB. Não é uma implantação na Internet.
O backend, além de loopback, exige **mTLS interno com outra CA** e a identidade
exata do serviço gateway. Estar em localhost, sozinho, não autorizaria um processo.

Para estudar cada processo em terminais diferentes, use `./scripts/run-backend.sh`
e `./scripts/run-gateway.sh --diagnostics`, **sem executar `run-lab.sh` ao mesmo tempo**.
Nesse modo os logs aparecem nos próprios terminais.

## Fluxo completo

```text
BUILD
VM: shared-client.key + shared-client.crt + ca.crt
  → shared-client.p12 + senha gerada
  → assets/mtls/client.p12 + classe Java gerada no APK
  → APK FUNCIONAL SEM DEXGUARD nesta v0.1
    (etapa comercial de proteção ainda pendente)

PRIMEIRO USO
alias ausente → asset → parser PKCS12 → validação
  → AndroidKeyStore.setEntry(PrivateKeyEntry, KeyProtection)
  → mtls-embedded-v1

REQUEST NORMAL
AndroidKeyStore → X509ExtendedKeyManager → SSLContext
  → TLS/mTLS + CA/hostname/pinning do GATEWAY
  → Gateway valida o cliente e sua geração
  → descarta headers externos reservados e cria metadata do handshake
  → NOVA conexão: mTLS interno com identidade de SERVIÇO
  → Backend Python, representando Spring, valida gateway e metadata
  → Backend valida sessão de USUÁRIO e autoriza /account
```

Se o alias válido já existe, inclusive após reiniciar o processo, o provider usa
o Keystore sem abrir o asset. O PKCS#12 precisa conter exatamente uma private key
entry esperada. Antes de importar, o app verifica cadeia, CA esperada, validade,
BasicConstraints, KeyUsage, `clientAuth`, algoritmo/tamanho, fingerprint da geração
e correspondência da chave privada com a pública por assinatura/verificação.

Depois de importar, valida o handle do Keystore, origem `IMPORTED` e
`privateKey.getEncoded() == null`. Faz limpeza **best effort** dos arrays de P12 e
senha; Strings, provider e VM podem manter cópias. Não persiste P12/senha em
SharedPreferences, DataStore, filesDir, cacheDir ou SQLite do app.

Durante um handshake mTLS completo, a implementação TLS envia certificados e
prova posse da chave usando a assinatura **CertificateVerify**. Não transmite
o `.p12`, a private key ou sua senha. A chave é importada, não gerada por instalação.
O indicador local de hardware não é attestation remota e não muda essa origem.

## Usar o app e autenticar uma conta

1. Toque **Import / Check Credential**. Veja alias, origem, fingerprint, validade,
   contador de leituras, indicador local de hardware e `getEncoded() == null`.
2. Toque **Test mTLS Gateway** ou **Show mTLS Identity**. O retorno deve informar
   `mtls_termination: API_GATEWAY` e `unique_device_identity: false`.
3. Teste **Primary Pin**, **Backup Pin** e **Unpinned Server**. Os dois primeiros
   passam; o último só é marcado como PASS quando ocorre `Pin verification failed`.
4. Crie uma conta local para experimentar senha/TOTP e sessão:

```bash
.venv/bin/python -m common.manage create-user estudante
```

Digite uma senha de 12–128 caracteres no prompt oculto. O comando grava o perfil
de MFA em `.local/embedded/provision-estudante.json`, com permissão 600, e imprime
somente o caminho. Abra esse arquivo **localmente**, em ambiente privado, e cadastre
o `totp_secret` no autenticador como TOTP SHA-1, 6 dígitos, período de 30 segundos.
Esse segredo é apenas para cadastro do autenticador; o app mTLS não o exibe.
Não publique o perfil nem o inclua em capturas/logs.

5. No app, preencha conta, senha e código TOTP atual; toque **Login via mTLS**.
6. Toque **Get Account**. O backend exige a sessão, mesmo que mTLS já tenha passado.
7. **Test Without User Session** recebe 401; **Logout** invalida o token.

O token é opaco, expira em 15 minutos, fica só na memória do app e seu hash fica no
backend. Reiniciar o app exige novo login, mas preserva a identidade no Keystore.
O mesmo TOTP não pode ser reutilizado: aguarde o próximo código após um login.
Há limites locais de tentativas, não uma solução de controle de abuso distribuído.
**Esta v0.1 não implementa um validador JWT.** O teste de token com formato de JWT
confirma rejeição de sessão desconhecida. Spring/JWT real é uma etapa de migração.

## Ver os logs

Com o supervisor rodando, em outro terminal na pasta deste lab:

```bash
tail -F .local/gateway.log .local/backend.log
```

O gateway registra `EDGE_MTLS_VERIFIED`, geração/fingerprint públicos e
`spoofed_headers_removed`. O backend registra `USER_SESSION_CREATED` e
`ACCOUNT_AUTHORIZED`. `HTTP ... status=401` indica sessão recusada;
`TLS_RECUSADO_OU_CONEXAO_ENCERRADA` também pode ser uma desconexão, não prova por
si só um ataque. Os testes negativos verificam a causa pelo cliente.
Não se registram corpos, senha, bearer ou segredo TOTP. Contas e fingerprints nos
logs ainda são metadata de segurança e merecem política de retenção em produção.

## Pinning, mTLS e identidade de usuário

| Componente | Responsabilidade |
|---|---|
| KeyManager | selecionar certificado cliente e handle privado para autenticação TLS |
| TrustManager | validar o servidor e sua cadeia de confiança |
| SPKI pinning | restringir a identidade pública aceita do gateway |
| JWT/sessão | identificar usuário e dar base à autorização de negócio |
| RASP | proteção do processo/aplicativo; comercial, ausente nesta build |
| API Gateway | terminar mTLS externo e aplicar política da credencial |
| Backend/Spring | confiar somente no gateway autenticado e autorizar o usuário |

O app mantém a Network Security Configuration do modelo anterior: CA de laboratório,
hostname `localhost`, SHA-256 da SPKI principal e backup. A configuração gerada usa
`overridePins="false"`, não tem `debug-overrides` nem expiração que desative pins.
Nenhum TrustManager aceita tudo, e o HostnameVerifier padrão permanece ativo.
O pin se refere à chave do **gateway**, não ao certificado interno do backend.
Referência: [Android Network Security Configuration](https://developer.android.com/privacy-and-security/security-config).

## Por que não fazemos custom request encryption?

O JSON e os headers, inclusive `Authorization`, existem em texto no processo.
A camada de registros TLS cifra e autentica esses dados no transporte. O gateway
termina essa conexão e vê o HTTP; depois abre outra conexão cifrada ao backend.
Não há sigilo de ponta a ponta contra o próprio gateway neste desenho.

Não é necessário criar `AES encryptRequest()` ou `RSA encryptBody()`. O Keystore
participa da operação com a chave privada usada no handshake, não de um protocolo
caseiro para cifrar cada body. mTLS, pinning, sessão e RASP têm papéis diferentes;
nenhum substitui os outros.

## Material criptográfico e senha

Em `.local/embedded/` ficam as duas CAs e seus pares `.key/.crt`, os certificados
`server`, `backup-server`, `unpinned-server`, `shared-client`, `gateway-internal`
e `backend-internal`, além de `shared-client.p12` e `p12-password`.

| Formato/conceito | Significado neste lab |
|---|---|
| `.key` | chave privada da VM em PKCS#8/PEM; nunca publicar |
| `.crt` | certificado X.509 público, aqui codificado em PEM; liga chave pública, usos, emissor e validade |
| `.pem` | representação textual Base64 com delimitadores; pode conter dado público **ou segredo**, depende do conteúdo |
| CA | autoridade que assina certificados; `ca.key` assina a PKI externa e `internal-ca.key` a de serviços |
| `.p12` / PKCS#12 | contêiner de private key, certificado e CA; cifrado com senha disponível ao próprio app |
| SPKI | estrutura da chave pública; seu SHA-256 é o pin, diferente do fingerprint do certificado inteiro |
| `.keystore` | neste caso, chave de assinatura do APK debug; não é a identidade mTLS AndroidKeyStore |

PKCS#12 usa PBESv1/3DES e MAC SHA-1 por compatibilidade com o parser do Android 10
testado. Isso é um perfil legado, não recomendação de proteção forte do arquivo.
Os certificados usam SHA-256 e o TLS permanece TLS 1.2 ou superior. Reavaliar
PBES2/provider e matriz de dispositivos antes da migração. A própria biblioteca
alerta que [PKCS#12 não deve ser tratado como fronteira de segurança](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#pkcs12).

A senha é gerada em `.local/embedded/p12-password` e injetada em
`.local/generated-java/.../GeneratedCredential.java`; não passa como argumento de
comando e não entra no Git. **Na build funcional ela é recuperável no DEX**.
O teste estático encontrou o P12 intacto e sua senha no APK. Eles não são duas
barreiras fortes independentes. O APK distribuído continua contendo essa cópia
mesmo após importar a chave no Keystore. Veja [DEXGUARD.md](DEXGUARD.md).

## Política, validade e futura rotação

O gateway confia na CA e também exige o fingerprint e serial autorizados em
`.local/embedded/gateway-policy.json`. Outro certificado da mesma CA não basta.
A política é consultada por request, inclusive em conexões já autenticadas.

Para demonstrar retirada de uma geração inteira:

```bash
.venv/bin/python -m common.manage credential disable
# Test mTLS Gateway deve falhar com HTTP 403 após o handshake.
.venv/bin/python -m common.manage credential enable
```

Isso é deny/allow local, não implementação de CRL/OCSP ou cura de vazamento.
Uma chave comprometida não deve ser reabilitada em produção. A desativação atinge
todas as instalações dessa geração, inclusive usuários com sessão ainda válida.

Certificados finais duram 30 dias; CAs, 365 dias. `prepare`/`run-lab` verificam
validade e falham se expirar. Não remova a validação TLS para resolver expiração.
Não há renovação automática nem rotação completa nesta v0.1. Preserve o estado
antigo para análise; um reset consciente de PKI cria outra identidade e exige
rebuild/reinstalação, novos pins e perda/recriação das contas locais. Não apague
`.local/` como procedimento cotidiano de execução.

O desenho futuro é release N com `embedded-v1`; release N+1 com `embedded-v2` e
outro alias; gateway aceita as duas durante uma janela; telemetria mede adoção;
depois v1 é retirada. A estrutura da allowlist suporta mais de um fingerprint,
mas geração de v2, transição no app e rollout não estão implementados.
Validade curta deve ser compatível com o tempo real de atualização dos celulares.

## Testes e próximos passos

```bash
./scripts/test.sh
./scripts/inspect-apk.sh
```

O primeiro executa gateway/backend com TLS real e PKIs temporárias; não exige o
servidor manual e não modifica seu estado. O segundo inspeciona somente a build
funcional, salva evidência privada em `.local/validation/` e mostra booleanos,
sem revelar chave/senha. Testes Android e resultados estão em [VALIDATION.md](VALIDATION.md).

Para v0.2: validar DexGuard/RASP comercial e build protegida; integrar cliente
OkHttp/Retrofit e gateway reais; implementar Spring Security/JWT e autorização;
exercitar rotação/retirada, múltiplos aparelhos e versões Android. O servidor HTTP
Python é didático, sem recursos de WAF, HTTP/2, alta disponibilidade ou identidade
exclusiva por aparelho. Não é um gateway de produção.

## Git

Publique código e documentação. `.local`, `.venv`, builds, APKs, chaves, P12,
senhas, bancos, perfis MFA, logs e material comercial ficam ignorados. O APK deste
lab contém uma chave compartilhada por desenho e também é material sensível.
Nunca use `git add -f` para incluir esses arquivos.

```bash
git status --short
git status --short --untracked-files=all
```

Não foi feito commit nem push nesta implementação.
