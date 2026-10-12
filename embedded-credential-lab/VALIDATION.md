# Validação executada — 12/10/2026

Esta evidência vale para a build funcional **sem DexGuard/RASP**, executada nesta
VM Debian. Não é validação de gateway comercial, Spring Boot, OkHttp/Retrofit ou
release protegida. Os dois labs anteriores não foram alterados para os testes.

## Ambiente e comandos

- Python 3.13, cryptography 50.0.1, OpenSSL da VM.
- JDK 21, Gradle 8.11.1, AGP 8.9.2, compile/target SDK 35, min SDK 26.
- Um único aparelho: **Motorola Moto G8 Play, Android 10/API 29** via ADB.
- Package `lab.mtls.embedded`; APK de instrumentação separado `lab.mtls.embedded.test`.
- Gateway real em processo separado do backend, PKI interna diferente da externa.

```bash
source /home/lucas/Documents/Codex/2026-09-17/x20/outputs/mtls-android/env.sh
cd /home/lucas/Documents/Codex/2026-09-17/x20/outputs/android-mtls-lab/embedded-credential-lab
./scripts/build-android.sh
./scripts/test.sh
./android/gradlew -p android --no-daemon --max-workers=2 assembleDebug assembleDebugAndroidTest lintDebug
./scripts/inspect-apk.sh
```

Resultado: **24 testes Python passaram**, build dos dois APKs passou e lint
concluiu com **0 erros e 3 avisos SetTextI18n** na UI de diagnósticos. Há uso de
APIs de instrumentação legadas no APK de testes para evitar adicionar outro stack
ao lab. Isso não é teste de localização/acessibilidade completa.

## Gateway/backend — TLS real, não mocks do handshake

`tests/test_boundary.py` inicia servidores de teste em portas efêmeras com PKIs
temporárias. Verifica resultado e falha efetiva, não apenas um log esperado.

| Caso executado | Resultado observado |
|---|---|
| Shared cert válido, cadeia e chave corretas | 200 e metadata correspondente |
| Sem cert, enviando headers internos falsos | handshake rejeitado; headers não autorizam |
| Certificado de CA externa não confiável | TLS rejeitado |
| Certificado cliente expirado | TLS rejeitado |
| Certificado com EKU incorreto | TLS rejeitado |
| Outro clientAuth válido assinado pela mesma CA | HTTP 403 pela allowlist |
| Headers internos forjados, duplicados e com casing alternativo | gateway recria metadata; fingerprint real chega ao backend |
| Acesso local direto ao backend sem identidade de serviço | TLS rejeitado |
| Credencial Android usada diretamente no backend | TLS rejeitado pela CA interna |
| Outro serviço da CA interna | 403, pois não é o fingerprint do gateway |
| Gateway autenticado, mas metadata ausente/duplicada/inconsistente | request rejeitada |
| Backend em loopback; tentativa na interface não-loopback da VM | bind somente local e conexão externa recusada |
| mTLS válido + bearer ausente/inválido com formato JWT | HTTP 401 |
| Senha + TOTP → sessão → conta → logout | autorizado e depois token recusado |
| Senha errada e replay TOTP | recusados |
| Sessão expirada | HTTP 401 |
| Geração desabilitada com sessão antes válida | HTTP 403 |
| Duas cópias do mesmo PKCS#12 em clientes por software | mesmo fingerprint; token ligado à geração pode ser usado por ambas |
| Tentativa de `/provision`/rotas de RASP; negócio no listener health | rotas ausentes, não há entrega HTTP de P12 |
| Listeners principal/backup/unpinned | todos têm TLS/CA/hostname válidos, mas SPKIs diferentes |
| Inputs Android gerados | P12/senha fora de source versionável; pins sem override permissivo |
| Servidor interno não confiável | gateway falha fechado, HTTP 502 |
| Gateway sem certificado interno | falha interna, HTTP 502 |
| Content-Length excedendo limite | HTTP 413 sem ler o body inteiro |

O teste com texto `invalid.jwt.token` **não demonstra validação criptográfica de
JWT**: o backend implementa sessão opaca e rejeita token desconhecido. A migração
Spring deve testar assinatura, issuer/audience, expiração e autorização reais.

O teste explícito de spoofing sem certificado envia:

```text
X-Internal-MTLS-Verified: SUCCESS
X-Internal-MTLS-Fingerprint: fake
```

Ele falha no TLS externo. Outro teste envia os mesmos valores com certificado
válido: a request passa, mas o backend recebe o fingerprint real e a geração da
allowlist. Acesso direto com esses headers falha na autenticação do serviço.

## Android físico — resultados executados

| Etapa | Resultado observado no Moto |
|---|---|
| Instalar APK funcional e APK de testes | `Success` nos dois |
| `mode first` | alias inicialmente ausente; importado; presente; somente uma leitura do asset em duas chamadas |
| Chave importada | origem `IMPORTED`, `privateKey.getEncoded()==null` |
| Indicador local de hardware | `true`, apenas observação local; não attestation remota |
| Force-stop e `mode persist` em novo processo | zero leituras do asset; mTLS continua funcionando |
| Prova de ausência de releitura | AssetSource de teste lança exceção se houver tentativa de abrir o P12; teste passou |
| `mode network`: principal/backup | ambos passam |
| Mesma CA/hostname e chave fora dos pins | `Pin verification failed`; teste só aceita essa causa |
| Headers internos forjados no Android | fingerprint real preservado no retorno |
| Sem sessão e bearer inválido, com mTLS válido | HTTP 401 |
| Sem client certificate | falha SSL com serviço disponível |
| Desinstalar e reinstalar `lab.mtls.embedded`; `mode reinstall` | alias ausente novamente, uma importação, mesmo fingerprint |
| UI: Login via mTLS com senha/TOTP, Get Account e Logout | sessão autenticada, conta retornada e sessão encerrada; zero releituras do asset |
| UI: resposta de /account | `mtls_termination=API_GATEWAY`, `internal_peer=gateway-internal`, canal interno `TLSv1.3` |

No teste inicial de UI o aparelho estava bloqueado por PIN; o usuário o desbloqueou.
Uma tentativa de consulta coincidiu com o reinício controlado dos serviços e perdeu
a conexão. O ciclo completo foi repetido depois do reinício e passou com os serviços
estáveis. Nenhuma senha, token ou segredo TOTP foi incluído na evidência publicada.

Também foi executada uma segunda chamada a `run-lab.sh` com as portas já ocupadas:
ela foi recusada e preservou os processos existentes. SIGTERM ao supervisor deste
lab encerrou ambos os filhos; a nova execução iniciou gateway e backend separados.
Os listeners 8643/8650 foram conferidos em loopback e o ADB encaminha apenas
8643–8646. Os serviços foram deixados rodando após a validação.

Fingerprint público observado antes/depois de reiniciar e reinstalar:

```text
79ec4e5c45679ed2629817cfb75231015983266dcef2da4a802bc91accb9801b
```

Outra VM/preparação terá outra identidade; não use esse valor como constante de
configuração. A fonte de configuração do app é gerada a partir da PKI local.

Para reproduzir com o gateway/backend rodando, **primeiro** instale pelo
`connect-phone.sh` e instale a instrumentação:

```bash
adb install -r android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
# Só funciona se o alias ainda estiver ausente. Não toque Import antes deste modo.
adb shell am instrument -w -e mode first lab.mtls.embedded.test/lab.mtls.embedded.EmbeddedTestRunner
adb shell am force-stop lab.mtls.embedded
adb shell am instrument -w -e mode persist lab.mtls.embedded.test/lab.mtls.embedded.EmbeddedTestRunner
adb shell am force-stop lab.mtls.embedded
adb shell am instrument -w -e mode network lab.mtls.embedded.test/lab.mtls.embedded.EmbeddedTestRunner
```

Com mais de um aparelho, use `adb -s SERIAL`. Confira a linha **PASS**, pois o
exit code do comando ADB sozinho não demonstra sucesso das assertions.
Se a importação já aconteceu, pule `first` e use `persist`/`network`.

Teste de reinstalação **remove dados e alias deste app**; não toca os outros packages:

```bash
adb uninstall lab.mtls.embedded
./scripts/connect-phone.sh
adb shell am instrument -w -e mode reinstall lab.mtls.embedded.test/lab.mtls.embedded.EmbeddedTestRunner
```

Abrir a Activity não importa automaticamente; somente acionar import/rede o faz.
Compare o fingerprint com o anterior. Não use reinstalação como atualização
rotineira, pois ela também elimina sessão/dados locais do app.

## Extração estática da build funcional

`inspect-apk.sh` executou e confirmou:

```text
asset_present = true
asset_identical_to_original = true
password_literal_found_in_dex = true
openssl_pkcs12_parse_success = true
protected_comparison = NOT AVAILABLE / NOT VALIDATED
```

O relatório contém booleanos; não expõe senha ou private key. O arquivo extraído
fica privado em `.local/validation/extracted-client.p12`. Nenhum artefato protegido
foi gerado. A evidência mostra que **esta build não possui hardening estático**.

## Pendências e limites

- Segundo aparelho físico: indisponível; somente a comparação de dois clientes
  por software e a reinstalação do Moto foram executadas.
- DexGuard/plugin/licença: não disponível/validado. Build protegida e comparação:
  não executadas.
- RASP, Frida, root, debugger, tampering/repackaging: proteção não ativa; resistência
  não testada. Instrumentação Android usada como teste funcional, não prova de RASP.
- Spring/JWT, OkHttp/Retrofit e gateway comercial: pseudocódigo/design, não executados.
- Rotação completa, rollout multi-geração, carga, HTTP/2 e retomada TLS: pendentes.
- UI de login foi validada após desbloqueio pelo usuário; os testes Python também
  cobrem login/MFA/sessão/logout com os dois canais TLS reais.

## Git e isolamento

Chaves, P12, senha, perfis MFA, SQLite, logs, assinatura debug e inputs gerados ficam
ignorados. O código/README não contém segredos gerados. O APK contém a credencial
por desenho e também fica fora do Git. A revisão final compara hashes dos arquivos
versionados dos outros dois labs com a baseline anterior à implementação: os
**65 arquivos permaneceram idênticos**. Valores secretos gerados não foram
encontrados nos candidatos a versionamento; os artefatos privados foram conferidos
com `git check-ignore`. Nenhum commit ou push foi realizado.
