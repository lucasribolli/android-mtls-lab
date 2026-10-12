# Laboratórios Android mTLS

Três laboratórios para estudar e comparar a distribuição de credenciais mTLS
em um app Android comum, sem permissões privilegiadas. Cada um tem sua própria pasta,
projeto Android, serviços Python, ambiente virtual, PKI e documentação.
Todos pertencem a **este mesmo repositório Git**.

| Laboratório | Modelo de chave | Abrir as instruções |
|---|---|---|
| **Chave por instalação** | O Android Keystore gera uma chave exclusiva para cada instalação. O servidor valida a atestação antes de emitir o certificado. | [per-installation-lab/README.md](per-installation-lab/README.md) |
| **Credencial compartilhada** | O servidor entrega cópias da mesma chave por HTTPS com pinning, após autorização e RASP **simulado**. O app importa a chave no Keystore. | [shared-credential-lab/README.md](shared-credential-lab/README.md) |
| **Credencial compartilhada no APK** | O APK contém P12/senha; o app importa a chave no Keystore. mTLS termina no **API Gateway**, que chama um backend interno representando Spring por outro canal TLS autenticado. | [embedded-credential-lab/README.md](embedded-credential-lab/README.md) |

“Chave por instalação” significa que dois celulares com o mesmo APK geram chaves
diferentes. Reinstalar o app e cadastrá-lo novamente também gera outra identidade.
No modelo compartilhado, as instalações recebem a mesma chave criptográfica.

No terceiro lab, **DexGuard + RASP + AndroidKeyStore** é o desenho candidato de
proteção. **Só o Keystore está implementado/validado nesta build funcional**:
DexGuard está **NOT AVAILABLE / NOT VALIDATED**; RASP está **NOT ACTIVE / NOT VALIDATED**.
Não há RASP simulado, provisioning HTTP ou garantia de impossibilidade de extração.

## Estrutura

```text
android-mtls-lab/
├── README.md
├── per-installation-lab/
│   ├── README.md
│   ├── android/
│   ├── server/
│   └── scripts/
├── shared-credential-lab/
│   ├── README.md
│   ├── COMPARISON.md
│   ├── VALIDATION.md
│   ├── android/
│   ├── server/
│   └── scripts/
└── embedded-credential-lab/
    ├── README.md
    ├── ARCHITECTURE.md
    ├── THREAT_MODEL.md
    ├── VALIDATION.md
    ├── DEXGUARD.md
    ├── android/
    ├── gateway/
    ├── backend/
    ├── common/
    ├── tests/
    └── scripts/
```

Dentro de cada laboratório, `.local/` guarda o estado privado gerado na preparação
e o ambiente Python fica em `server/.venv/` nos dois primeiros ou `.venv/` no
terceiro. Esses diretórios, chaves, logs,
APKs e resultados de build estão ignorados pelo Git. A raiz mantém os arquivos
comuns do repositório; os comandos de execução ficam na pasta de cada laboratório.

## Escolher o laboratório

Configure os pré-requisitos descritos no README escolhido. Na VM já preparada,
os caminhos de Java/SDK podem ser carregados com:

```bash
source /home/lucas/Documents/Codex/2026-09-17/x20/outputs/mtls-android/env.sh
cd /home/lucas/Documents/Codex/2026-09-17/x20/outputs/android-mtls-lab
```

A partir da raiz do repositório, para a chave por instalação:

```bash
cd per-installation-lab
./scripts/build-android.sh
./scripts/run-server.sh
```

Ou, também a partir da raiz, para a credencial compartilhada:

```bash
cd shared-credential-lab
./scripts/build-android.sh
server/.venv/bin/python server/lab.py rasp approved
./scripts/run-server.sh --diagnostics
```

Ou, a partir da raiz, para a credencial embutida e gateway separado:

```bash
cd embedded-credential-lab
./scripts/build-android.sh
./scripts/run-lab.sh
```

Cada servidor ocupa o terminal enquanto executa. Use outro terminal para criar
contas, instalar o app e acompanhar logs, seguindo o README daquele laboratório.
O comando `rasp approved` só aprova a **simulação**; não detecta root ou Frida.

| Pasta | Pacote Android | mTLS | HTTPS de cadastro/entrega | Diagnósticos |
|---|---|---|---|---|
| `per-installation-lab/` | `lab.mtls` | 8443 | 8444 | — |
| `shared-credential-lab/` | `lab.mtls.shared` | 8543 | 8544 | 8545 / 8546 |
| `embedded-credential-lab/` | `lab.mtls.embedded` | 8643 (gateway) | —; 8644 somente health | 8645 / 8646 |

O terceiro também usa **8650**, backend em loopback com **mTLS de serviços**,
sem encaminhamento ADB. O Android só alcança o gateway e seus diagnósticos.
Os três apps e serviços usam pacotes/portas diferentes e podem coexistir.
As contas e credenciais são independentes.
Para abrir no Android Studio, escolha `per-installation-lab/android/` ou
`shared-credential-lab/android/` ou `embedded-credential-lab/android/`.
No VS Code, abra a raiz para navegar pelos três.

## Comparar as três abordagens

| Propriedade | Per-installation | Shared Remote | Shared Embedded |
|---|---|---|---|
| Chave privada criada | Dispositivo | Servidor | VM/build backend |
| Distribuição | Certificado emitido pelo servidor; chave fica no cliente | P12 por provisioning HTTPS com pinning | P12/senha no APK |
| Chave privada compartilhada | Não | Sim | Sim |
| Identidade vista no backend | Instalação cadastrada | Credencial da aplicação/geração | Credencial da aplicação/geração, declarada pelo gateway |
| Rotação sem atualizar app | Possível | Possível pelo canal de provisioning | Geralmente exige novo release |
| Alcance de comprometimento da chave cliente | Instalação afetada | Todas as cópias da geração | Todas as cópias da geração |
| Dependência relativa de application shielding | Menor | Média | Alta |
| Complexidade de lifecycle | Alta | Média | Menor no início; rollout de updates pesa na rotação |
| Terminação mTLS externa no lab | Servidor Python | Servidor Python | Gateway Python separado |
| Autenticação de usuário | Login/MFA e sessão | Login/MFA e sessão | Login/MFA e sessão no backend interno |

Dependência de shielding e complexidade são avaliações qualitativas da arquitetura,
não métricas obtidas em teste. Chave por instalação também precisa proteger o app.
“Possível” não significa rotação completa implementada: o primeiro lab possui
renovação por mTLS; rotação completa de gerações shared/rollout permanece pendente.
Em todos os modelos, mTLS não substitui pinning nem autenticação/autorização do usuário.

## Estudo e comparação

- [Fluxo completo: chave gerada no cliente e atestação](per-installation-lab/README.md#fluxo-completo)
- [Fluxo completo: entrega da credencial compartilhada](shared-credential-lab/README.md#fluxo-completo)
- [Comparação técnica inicial](shared-credential-lab/COMPARISON.md)
- [Validação da credencial compartilhada no Xiaomi](shared-credential-lab/VALIDATION.md)
- [Fluxo completo: credencial no APK e gateway](embedded-credential-lab/README.md#fluxo-completo)
- [Migração Android + API Gateway + Spring Boot](embedded-credential-lab/ARCHITECTURE.md#migration-to-android--api-gateway--spring-boot)
- [Validação do terceiro lab no Moto G8 Play](embedded-credential-lab/VALIDATION.md)
- [Limitações, extração e risco de geração compartilhada](embedded-credential-lab/THREAT_MODEL.md)

O laboratório com chave por instalação ficava anteriormente na raiz. Seu conteúdo
agora está em `per-installation-lab/`; use esse novo caminho para os comandos e para
abrir o projeto no Android Studio. Na VM desta migração, contas, PKI e assinatura do
APK foram preservadas, e o ambiente Python foi recriado no novo local.
