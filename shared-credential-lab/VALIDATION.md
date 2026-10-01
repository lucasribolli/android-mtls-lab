# Registro de validação

Execução em **30/09/2026 e 01/10/2026**, na VM Debian e no **Xiaomi Redmi Note 8,
Android 10**. Resultados observados para este ambiente; não representam certificação
de produção nem avaliação da eficácia de um RASP comercial.

## Servidor e build

- `python -m unittest discover -s server -v`: **20 testes passaram**. PKI, SQLite e
  portas efêmeras próprios, sem modificar o estado persistente do laboratório.
- `assembleDebug`: compilação concluída com sucesso, usando JDK 21 / AGP 8.9.2 /
  Gradle Wrapper 8.11.1 / compile SDK 35.
- `lintDebug`: concluído sem erros. Interface didática em português contém avisos de
  internacionalização; não é uma interface localizada para distribuição na Play Store.
- Script de reinício: encerrou a instância anterior deste `server/lab.py`, abriu uma
  nova e preservou PKI, banco e configuração. O servidor do outro lab não é alvo do script.
- `.local`, `.venv`, builds, APKs, CA/pins gerados e chaves locais estão ignorados pelo Git.
  Não existe `.git` aninhado em `shared-credential-lab/`.

## Resultados no Xiaomi

| Experimento | Resultado observado |
|---|---|
| HTTPS com pin principal, porta 8544 | HTTP 200, listener `bootstrap` |
| HTTPS com pin de reserva, porta 8546 | HTTP 200, listener `backup` |
| Certificado válido da mesma CA, com chave fora dos pins, porta 8545 | Recusa específica `Pin verification failed` |
| Login/MFA correto + RASP DEMO bloqueado | HTTP 403; nenhuma credencial importada |
| RASP DEMO aprovado + entrega autorizada | P12 recebido por HTTPS e importado no AndroidKeyStore |
| Origem da chave após importação | `IMPORTED (2)` |
| `KeyInfo.isInsideSecureHardware()` | `true`, informação local; não validada por atestação remota neste lab |
| `PrivateKey.getEncoded()` após importação | `null`: a API do Keystore não exportou a chave |
| Login/MFA por mTLS | Sessão de usuário criada |
| Consulta de conta com certificado + sessão | HTTP 200 para a conta de teste, **TLS 1.3** |
| API sem certificado cliente | Recusa TLS com `TLSV1_CERTIFICATE_REQUIRED` |
| API com certificado, mas sem sessão | HTTP 401 |
| Credencial compartilhada revogada no servidor | HTTP 403 no acesso com a chave ainda presente no Keystore |
| Atualização do APK e retomada | Mesmo alias ativo/fingerprint disponível; nenhuma nova entrega necessária |

Fingerprint SHA-256 público da credencial observada nesta execução:

```text
339e38122ee8027cffaade5191880de6b9be7a924b292147949f6543a3c39ea7
```

Outra preparação da PKI gera outro fingerprint. Ele é um identificador público,
não uma senha nem um pin do servidor.

## Compatibilidade que o teste físico revelou

O provider nativo deste Android 10 não abriu o PKCS#12 PBES2 produzido pelo padrão
atual do gerador (`SecretKeyFactory not available`, OID `1.2.840.113549.1.5.12`).
O container foi reempacotado com PBESv1/3DES + MAC SHA-1, preservando a mesma chave,
certificado e senha; a importação então funcionou. Esse perfil legado ficou explícito
em `server/pki.py` e no [README](README.md#compatibilidade-pkcs12-no-android-10).
O transporte permaneceu HTTPS com pinning; os certificados continuam RSA/SHA-256.

## Escopo da evidência

O teste Python `test_01_two_deliveries_same_private_key_and_certificate` confirmou
duas entregas do mesmo P12 e mTLS com duas cópias independentes. O teste de sessão
mostra que outro possuidor da mesma chave também satisfaz o vínculo do certificado
caso obtenha o token da sessão. O token continua necessário para a conta.
**Não foi usado um segundo aparelho físico nesta validação.**

Foi verificada no APK e nos novos arquivos visíveis ao Git a ausência dos bytes da
chave privada compartilhada, do P12 e da senha de transporte. O APK contém somente
a CA e os pins públicos necessários à confiança local.

O RASP foi simulado o tempo todo. Não se verificou resistência a root/Frida,
instrumentação, captura de memória ou uso indevido da chave por código no mesmo UID.
`getEncoded() == null` não demonstra que cópias anteriores da chave deixaram de existir.
A rotação distribuída da chave compartilhada e testes em outros modelos/versões Android
continuam fora do escopo deste primeiro laboratório.
