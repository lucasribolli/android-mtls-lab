# DexGuard / RASP — integração pendente

**DexGuard: NOT AVAILABLE / NOT VALIDATED. Proteção: NOT ACTIVE.**
**RASP: NOT ACTIVE / NOT VALIDATED.**

## Verificação nesta VM — 12/10/2026

A inspeção inicial procurou nomes de instalações/distribuições/documentação local
e referências de build no workspace e nos locais usuais de ferramentas/cache.
Não foi encontrada instalação DexGuard, versão de plugin Gradle ou documentação
local utilizável. Não foram abertos nem exibidos tokens ou conteúdo de licença.
Licença/entitlement não foi validado. Ausência de evidência local não é declaração
sobre os contratos ou ferramentas que o banco possa ter em outro ambiente.

Nenhuma sintaxe de plugin/regra DexGuard foi inventada. Este projeto usa AGP normal,
Java e debug signing local, com geração de inputs privados e release desabilitada.
Não existe um flavor chamado “protected” que simule proteção.

## Escopo a proteger quando o produto estiver disponível

| Alvo | Ponto de integração/objetivo a confirmar |
|---|---|
| `assets/mtls/client.p12` | evitar extração estática trivial; confirmar proteção de assets e sua interface de acesso |
| `GeneratedCredential` | senha e configuração geradas; confirmar mecanismos compatíveis de proteção de dados/strings |
| `EmbeddedMtlsCredentialProvider` | acesso ao asset e inicialização; preservar recuperação correta no primeiro uso |
| `CredentialValidator` e `AndroidKeyStoreCredentialStore` | parser/importação/validação e proteção dos caminhos de falha |
| `MtlsKeyManagerFactory` e `MtlsSslContextConfigurer` | preservar integração JSSE/AndroidKeyStore e uso do handle privado |
| NSC / pinning / networking do app real | impedir alterações indevidas sem enfraquecer trust, hostname ou pins |
| Inicialização e runtime | avaliar integridade, tampering, repackaging, root, debugger, hooking e instrumentação |

Asset/string/class encryption, control-flow obfuscation, virtualization e controles
de runtime são **itens de avaliação**, não recursos confirmados para alguma versão
ou licença. As capacidades e regras válidas precisam vir da documentação oficial
da distribuição efetivamente licenciada.

## Passos de integração ainda não validados

1. Disponibilizar distribuição/plugin e documentação da versão licenciada; registrar
   versão, compatibilidade AGP/JDK e modo de integração. Usar secret store para
   credenciais, sem registrar conteúdo da licença em Git/logs.
2. Consultar somente essa documentação para plugin, regras, proteções de assets,
   classes/dados e hooks de runtime. Não há comando DexGuard pronto nesta v0.1.
3. Criar build comercial separada da baseline funcional. Remover debuggability e
   APK de instrumentação da distribuição; preservar os diagnósticos necessários
   em uma estratégia de testes autorizada.
4. Confirmar suporte ao acesso `AssetManager.open("mtls/client.p12")`, reflection/
   JNI/providers, KeyManager callbacks, pins e reinício com alias persistente.
5. Validar RASP transversalmente no processo. Não adicionar aprovação fake, header
   `X-RASP`, proof ao backend ou provisioning condicionado por um booleano local.
6. Testar build protegida em aparelhos/versões representativas e em cenários de
   root/hooking/tampering definidos pelo time, registrando os resultados reais.

## Baseline estática executada

```bash
./scripts/inspect-apk.sh
```

Na build funcional de 12/10/2026, o ZIP continha `assets/mtls/client.p12`, os bytes
extraídos eram idênticos aos gerados, a senha literal estava presente em DEX e
OpenSSL abriu o contêiner com a senha local. O script usa `-passin file:...` e
`-noout`, não imprime senha/chave e salva somente booleans no relatório.
O asset extraído fica em `.local/validation/`, privado e fora do Git.

Quando existir build protegida, repetir a comparação separadamente: hash do asset
original versus bytes extraídos, tentativa `openssl pkcs12 -info -noout`, análise
dos caminhos de acesso e testes de comportamento. Este script atual é baseline
**sem proteção**, não um avaliador universal de DexGuard.

Falha em abrir um arquivo isolado não prova que uma chave é impossível de extrair:
pode indicar transformação, nome diferente ou até build quebrada. Só registrar
“extração estática dificultada sob a configuração X” com evidência e app funcional.
Não foi gerada nem comparada build protegida nesta entrega.

## Expectativa realista

Senha e P12 precisam ser utilizáveis pelo app legítimo. Proteção comercial busca
aumentar custo de análise/modificação e limitar runtime hostil; não transforma uma
chave distribuída em chave originalmente não exportável de hardware. Continua
necessário planejar comprometimento de geração inteira, validade, retirada no
gateway, update do app e autenticação/autorização de usuário.
