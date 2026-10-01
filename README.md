# Laboratórios Android mTLS

Dois laboratórios para estudar e comparar o provisionamento de credenciais mTLS
em um app Android comum, sem permissões privilegiadas. Cada um tem sua própria pasta,
projeto Android, servidor Python, ambiente virtual, PKI e documentação.
Ambos pertencem a **este mesmo repositório Git**.

| Laboratório | Modelo de chave | Abrir as instruções |
|---|---|---|
| **Chave por instalação** | O Android Keystore gera uma chave exclusiva para cada instalação. O servidor valida a atestação antes de emitir o certificado. | [per-installation-lab/README.md](per-installation-lab/README.md) |
| **Credencial compartilhada** | O servidor entrega cópias da mesma chave por HTTPS com pinning, após autorização e RASP **simulado**. O app importa a chave no Keystore. | [shared-credential-lab/README.md](shared-credential-lab/README.md) |

“Chave por instalação” significa que dois celulares com o mesmo APK geram chaves
diferentes. Reinstalar o app e cadastrá-lo novamente também gera outra identidade.
No modelo compartilhado, as instalações recebem a mesma chave criptográfica.

## Estrutura

```text
android-mtls-lab/
├── README.md
├── per-installation-lab/
│   ├── README.md
│   ├── android/
│   ├── server/
│   └── scripts/
└── shared-credential-lab/
    ├── README.md
    ├── COMPARISON.md
    ├── VALIDATION.md
    ├── android/
    ├── server/
    └── scripts/
```

Dentro de cada laboratório, `.local/` guarda o estado privado gerado na preparação
e `server/.venv/` guarda as dependências Python. Esses diretórios, chaves, logs,
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

Cada servidor ocupa o terminal enquanto executa. Use outro terminal para criar
contas, instalar o app e acompanhar logs, seguindo o README daquele laboratório.
O comando `rasp approved` só aprova a **simulação**; não detecta root ou Frida.

| Pasta | Pacote Android | mTLS | HTTPS de cadastro/entrega | Diagnósticos |
|---|---|---|---|---|
| `per-installation-lab/` | `lab.mtls` | 8443 | 8444 | — |
| `shared-credential-lab/` | `lab.mtls.shared` | 8543 | 8544 | 8545 / 8546 |

Os dois apps e servidores podem coexistir. As contas e credenciais são independentes.
Para abrir no Android Studio, escolha `per-installation-lab/android/` ou
`shared-credential-lab/android/`. No VS Code, abra a raiz para navegar pelos dois.

## Estudo e comparação

- [Fluxo completo: chave gerada no cliente e atestação](per-installation-lab/README.md#fluxo-completo)
- [Fluxo completo: entrega da credencial compartilhada](shared-credential-lab/README.md#fluxo-completo)
- [Comparação técnica inicial](shared-credential-lab/COMPARISON.md)
- [Validação da credencial compartilhada no Xiaomi](shared-credential-lab/VALIDATION.md)

O laboratório com chave por instalação ficava anteriormente na raiz. Seu conteúdo
agora está em `per-installation-lab/`; use esse novo caminho para os comandos e para
abrir o projeto no Android Studio. Na VM desta migração, contas, PKI e assinatura do
APK foram preservadas, e o ambiente Python foi recriado no novo local.
