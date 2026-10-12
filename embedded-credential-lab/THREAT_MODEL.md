# Threat model — shared credential no APK

A propriedade demonstrada é posse da credencial compartilhada perante o edge,
preservando autenticação do servidor e sessão de usuário. O gateway não identifica
exclusivamente uma instalação. O adversário pode obter o APK, enviar HTTP/TLS,
tentar headers falsos e analisar/instrumentar seu próprio aparelho. Compromisso
da VM, CA ou serviço gateway está fora das garantias de isolamento desta v0.1.

## Ameaças, controles e limites

| Ameaça | Mitigação implementada ou planejada | Risco residual / estado |
|---|---|---|
| Extração estática do APK | DexGuard para asset/configuração seria avaliado comercialmente | **Ausente**: o teste extraiu o P12 intacto e encontrou a senha no DEX. Mesmo com hardening, o app precisa acessar a credencial |
| Hooking/Frida/instrumentação | RASP/application shielding conforme produto, versão e licença | **Ausente/não validado**; não equivale a chave gerada e não exportável em hardware; não houve teste de resistência a Frida |
| Root/debugger/tampering/repackaging | Proteção comercial futura e validação de release | Build atual é debug e instrumentável; nenhuma detecção/proteção comercial é afirmada |
| Vazamento da shared private key | Validade de 30 dias, allowlist com `enabled`, retirada da geração e novo release | Todas as instalações da geração afetadas. Login ainda restringe dados de conta, mas a fronteira mTLS pode ser imitada |
| MITM no Android → gateway | TLS, CA esperada, hostname e pins SPKI principal/backup | Não protege contra processo cliente/edge comprometido; pinning exige lifecycle correto |
| Header `X-Internal-MTLS-*` forjado | Gateway cria headers novos a partir do peer real; backend valida serviço e metadata | Compromisso do gateway pode produzir metadata falsa; testes cobrem chamadas externas e diretas |
| Acesso direto ao backend | Bind em 127.0.0.1, sem reverse ADB, mTLS interno e fingerprint de serviço | Root/mesmo usuário Linux pode ler chaves locais; produção exige isolamento de workloads e de segredos |
| Serviço interno diferente tentando se passar pelo gateway | CA de serviço separada + fingerprint exato | Furto de `gateway-internal.key` quebra essa autenticação; esse segredo não é a chave Android |
| Token de sessão inválido/ausente | Backend exige sessão opaca válida de 15 minutos, hash no banco | Certificado mTLS válido sozinho não acessa /account; não há JWT real na v0.1 |
| Furto de bearer junto com shared key | Expiração/logout, transporte TLS, ausência de token em logs/UI | Token é vinculado ao fingerprint compartilhado, **não a um aparelho**; outra cópia pode reutilizar um token roubado |
| Senha/TOTP e replay | scrypt, TOTP, recusa de contador já usado e limites locais | Demonstração de MFA, sem recuperação/IdP/antifraude/distribuição real. Segredos de administração local exigem proteção |
| APK antigo | Expiração e política de geração; novo release e retirada de v1 | APK antigo continua contendo chave antiga. Controle de versão mínima, se adotado, deve ter evidência confiável; header de versão não prova integridade |
| Expiração antes de adoção de novo app | Plano de sobreposição v1/v2 e telemetria, ainda não implementado | Pode derrubar toda a base dessa geração; prazo de 30 dias é didático, não dimensionamento bancário |
| Vazamento no build/CI | `.local` ignorado, arquivos privados, senha fora da linha de comando, APK ignorado | Build host e artefato contêm a chave. `.gitignore` não corrige um segredo já publicado nem substitui secret scanning |
| Memória do importador | Limpeza best effort de arrays e uso posterior do handle Keystore | Java/provider/Strings podem reter cópias; não se promete zeroização perfeita |
| Negação de serviço/parser/proxy | Limites de corpo, timeouts e workers; rotas fixas; rejeição de framing ambíguo | Python didático, sem capacidade de WAF/DDoS/produção; testes não são auditoria de parser |

## O que o Keystore muda e o que continua existindo

Depois da importação, requests usam um handle de private key cujo `getEncoded()`
foi `null` no Moto testado. Isso reduz exportação pela API do Keystore. Porém a VM
gerou a chave e o APK distribuiu a mesma chave para toda instalação. A cópia
original não desaparece do pacote. Não é equivalente ao modelo por instalação,
no qual a chave nasce no dispositivo e uma attestation pode ser validada remotamente.

O indicador de hardware reportado localmente não certifica ausência de hooking,
não é prova Google/OEM validada no servidor e não individualiza essa chave.
Não se depende do fabricante conceder permissões privilegiadas ao app: ele usa
APIs comuns AndroidKeyStore e somente permissão INTERNET.

## Rotação e resposta a comprometimento

1. Desabilitar a geração comprometida na política do gateway e backend. A recusa
   vale para toda a geração e interrompe o acesso, mesmo com sessão válida.
2. Gerar outra chave/certificado e publicar outro release protegido após validação.
3. Em rotação planejada, aceitar v1 e v2 temporariamente, medir adoção e retirar v1.
   Em incidente, sobreposição com a chave comprometida prolonga a exposição.
4. Rever tokens/sessões, indicadores de abuso e distribuição do APK comprometido.

Somente `credential enable/disable` está implementado; emissão/rollout v2,
CRL/OCSP, telemetria de adoção e resposta automatizada ainda são TODOs.

## Limites da evidência

Os testes comprovam os casos descritos em [VALIDATION.md](VALIDATION.md), usando
uma VM e um Moto G8 Play. Não houve segundo aparelho físico, build protegida,
ataque dinâmico, teste de carga ou integração Spring/OkHttp/gateway comercial.
O segundo cliente por software prova a propriedade de identidade compartilhada,
sem substituir validação em vários modelos de telefone.
