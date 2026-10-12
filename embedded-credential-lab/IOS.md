# Equivalente iOS — proposta, sem implementação ou testes

Documento consultado/redigido em **12/10/2026**. Complementa o
[resumo no README](README.md#equivalente-ios--arquitetura-proposta-e-cuidados)
sem modificar Android, gateway ou backend. Não contém código Swift pronto,
projeto Xcode, comandos de distribuição ou regras comerciais.

| Escopo | Estado neste repositório |
|---|---|
| Android + gateway/backend Python | Implementados; evidências em [VALIDATION.md](VALIDATION.md) |
| Equivalente iOS / Security.framework / URLSession | Arquitetura proposta; **NOT IMPLEMENTED / NOT VALIDATED** |
| Spring Boot e JWT reais | Proposta de migração; o backend atual usa sessão opaca |
| DexGuard Android | NOT AVAILABLE / NOT VALIDATED |
| iOS shielding/RASP | **NOT IMPLEMENTED / NOT VALIDATED** |

Os resultados do Moto, inclusive Keystore em hardware reportado localmente,
pinning e reinstalação, não são evidência de comportamento iOS.

## Cenário B: a fronteira continua no gateway

```text
iOS: identidade compartilhada no Keychain + URLSession existente
    │ HTTPS: trust/hostname + pinning do gateway + client authentication
    ▼
WAF / Load Balancer / API Gateway — termina o mTLS externo
    │ descarta X-Internal-MTLS-* externos
    │ cria status/fingerprint/serial/geração a partir do cliente autenticado
    │ NOVA conexão interna autenticada
    ▼
Spring: autentica o serviço gateway → confere metadata → valida JWT/sessão
    │ autorização de negócio
    ▼
Endpoint
```

Preservar os controles em [ARCHITECTURE.md](ARCHITECTURE.md): certificado cliente
obrigatório, cadeia/CA, validade, `clientAuth`, KeyUsage e política explícita da
geração. Outro certificado da mesma CA não deve ganhar autorização automática.
Headers recebidos de fora não provam mTLS; são descartados e reconstruídos no edge.
O backend só confia neles depois de autenticar o canal e o gateway, com isolamento
de rede. A mudança Android → iOS não altera essas exigências.

Spring não recebe o handshake original do iPhone. Se o trecho interno usar mTLS,
o peer TLS é o serviço gateway; um atributo X509 do servlet não representa o
certificado mobile. O gateway vê HTTP em claro no processo e depois o transmite
em outro canal cifrado. Não há sigilo contra o próprio gateway nem necessidade
de `encryptRequest()`/protocolo caseiro: TLS já fornece criptografia de transporte.
Login, MFA, JWT/sessão e autorização permanecem independentes da shared identity.

## Build, bundle e distribuição da geração

O equivalente proposto de `assets/mtls/client.p12` é um **recurso do bundle iOS**,
adicionado durante o build a partir de diretório privado. Uma configuração pública
central deve identificar versão, certificado/fingerprint esperado, CA, algoritmo,
domínios e pins. A senha seria injetada por input gerado separado do código
versionado. Não existe essa configuração Xcode nesta entrega.

P12, private key, senha e inputs secretos nunca entram no Git, stdout, logs,
argumentos de comandos, crash reports ou anexos de suporte. Tratar também IPA,
`.xcarchive`, outputs intermediários, DerivedData/caches e artefatos de CI como
potenciais portadores da credencial: acesso mínimo, retenção definida e limpeza
controlada. Um arquivo ignorado pelo Git não é um secret store. Não salvar cópias
adicionais do P12/senha em UserDefaults, caches ou banco local do app.

O app precisa obter P12 e senha em runtime. A senha não constitui uma segunda
barreira forte independente. A Apple desaconselha embutir senhas; este documento
registra o custo de manter a arquitetura escolhida, sem atribuir aprovação a ela.
A importação não remove o recurso do bundle. Assinatura, sandbox e distribuição
não provam que a identidade não possa ser extraída.
[Apple: Importing an Identity](https://developer.apple.com/documentation/security/importing-an-identity).

| Distribuição proposta | Alcance de comprometimento e operação |
|---|---|
| Uma geração com a mesma chave/certificado para Android e iOS | Menos gerações para operar, mas um vazamento compromete as duas plataformas; retirada conjunta |
| Gerações separadas, com **chaves e certificados distintos** por plataforma | Permite política, release e retirada independentes; aumenta inventário, testes e telemetria; cada geração ainda afeta todos os seus usuários |

Emitir dois certificados sobre **a mesma private key** não isola seu vazamento.
Gerações distintas não individualizam aparelhos. O gateway prova posse da chave
da geração, não “este é o iPhone A” nem “este processo está íntegro”. A decisão
de separar plataformas deve ser explícita e refletida na allowlist; esta tarefa
não gera material novo nem muda `credential.json` do Android.

## Importação, persistência e reutilização

Fluxo proposto com Security.framework, executado fora da thread principal e
serializado por geração:

1. Consultar a identidade candidata com Keychain Services (`SecItemCopyMatching`),
   limitando classe/grupo/identificação esperados. Ausência é diferente de erro de
   acesso ou chave indisponível enquanto bloqueado.
2. Recuperar certificado/chave da `SecIdentity` e validar geração e perfil. Se
   estiver válida, reutilizar sem ler o recurso do bundle.
3. Se realmente faltar uma identidade utilizável, abrir o P12 em memória. Um erro
   transitório de bloqueio não deve disparar importações repetidas ou reduzir proteção.
4. Chamar `SecPKCS12Import` com a passphrase e conferir `OSStatus`. Inspecionar o
   conjunto retornado; aceitar **exatamente uma identidade privada esperada**, não
   simplesmente o primeiro item. Distinguir erro de formato de falha de importação;
   `errSecAuthFailed` também pode indicar dados danificados, não só senha incorreta.
5. Validar a identidade candidata integralmente antes de persistir/ativar.
6. Persistir pelo procedimento de Keychain Services para iOS, tratar duplicidade
   e recuperar o item novamente para conferir identidade e política de acesso.
7. Somente após sucesso publicar a identidade ativa para o networking. Em erro,
   manter a identidade anterior se ela ainda for válida/autorizada; nunca usar uma
   identidade expirada como fallback de disponibilidade.
8. Nas requests, fornecer a `SecIdentity` recuperada à URLSession. Não abrir P12
   por request ou handshake. Liberar referências temporárias e limpar buffers
   controláveis; Swift `Data`, Strings, bridging e providers podem manter cópias.

`SecPKCS12Import` retorna identidades/certificados e dados para avaliar trust; isso
não comprova trust nem persistência adequada à política do app. A nota de
persistência automática em keychain padrão é específica de macOS. Para iOS, usar
o passo explícito de Keychain Services e verificar o resultado, sem copiar fluxos
de `SecKeychain`/Keychain Access do Mac.
[SecPKCS12Import](https://developer.apple.com/documentation/security/secpkcs12import(_:_:_:))
e [Importing an Identity](https://developer.apple.com/documentation/security/importing-an-identity).

### Validação da identidade candidata

Exigir o perfil equivalente ao do [CredentialValidator Android](android/app/src/main/java/lab/mtls/embedded/CredentialValidator.java):

- Uma identidade com private key, certificado esperado e cadeia completa pertinente.
- CA esperada, assinaturas da cadeia, validade temporal e BasicConstraints corretos
  (leaf não-CA; emissores com capacidade de CA e uso de assinatura de certificado).
- KeyUsage apropriado à assinatura TLS e EKU `clientAuth` presente.
- Algoritmo/tamanho explicitamente suportados; a baseline atual é RSA 2048.
- SHA-256 do **certificado inteiro** igual ao fingerprint da geração. Não confundir
  esse fingerprint cliente com o hash SPKI usado no pin do servidor.
- Correspondência privada/pública, por exemplo assinando um desafio aleatório e
  verificando com a chave do certificado via operações Security.framework.

Avaliar trust com policy apropriada a certificado **cliente** e anchors esperados;
não reaproveitar cegamente uma policy de servidor/hostname. `kSecImportItemTrust`
é um objeto a avaliar, não um selo de aprovação. A avaliação de cadeia/policy é
fornecida por [SecTrustEvaluateWithError](https://developer.apple.com/documentation/security/sectrustevaluatewitherror(_:_:)).
As verificações adicionais de perfil exigem parser X.509/APIs disponíveis no iOS
alvo; selecionar e validar isso na implementação, sem supor que APIs de inspeção
exclusivas do macOS existam no iPhone. Não há biblioteca de parsing validada aqui.

O perfil PKCS#12 legado da baseline Android foi testado naquele Android, não no
iOS. Confirmar importação, algoritmos do contêiner e política criptográfica no SDK
e aparelhos escolhidos, sem trocar formatos silenciosamente nem relaxar a validação.

### Persistir e localizar sem inventar um alias Android

O procedimento Apple é usar `SecItemAdd` com `kSecClassIdentity` e `kSecValueRef`
apontando para a `SecIdentity`; recuperar com `SecItemCopyMatching` e
`kSecReturnRef`. Um `kSecAttrLabel` versionado pode auxiliar a busca, seguindo o
procedimento de certificados com a classe de identidade. É um identificador de
aplicação, não garantia de unicidade nem autorização.
[Storing an Identity in the Keychain](https://developer.apple.com/documentation/security/storing-an-identity-in-the-keychain)
e [Storing a Certificate in the Keychain](https://developer.apple.com/documentation/security/storing-a-certificate-in-the-keychain).

Keychain representa a identidade pela associação entre certificado e chave,
armazenados separadamente. Não há equivalência exata com o alias Android.
`kSecAttrApplicationTag` serve para identificação de **chaves** quando usadas as
operações dessa classe; não copiar atributos de senha, como account/service, para
consultas de identidade. Não sobrescrever `kSecAttrApplicationLabel` com texto de
versão: ele participa da associação da chave com o certificado. Sempre confirmar
o certificado/fingerprint após localizar um candidato.
[kSecClassIdentity](https://developer.apple.com/documentation/security/ksecclassidentity)
e [Storing Keys in the Keychain](https://developer.apple.com/documentation/security/storing-keys-in-the-keychain).

Definir atributos de proteção suportados pela classe/SDK e conferir os atributos
efetivamente persistidos, sobretudo da private key. O suporte de label e
acessibilidade é descrito em [kSecClassCertificate](https://developer.apple.com/documentation/security/ksecclasscertificate),
e a identidade combina atributos de certificado e chave. A implementação precisa
validar a combinação escolhida em dispositivos reais, incluindo os componentes
preexistentes de uma identidade duplicada.

`errSecDuplicateItem` não significa que a identidade encontrada seja a esperada.
A unicidade da identidade segue a chave primária composta do certificado, não
apenas seu label. Ao receber duplicidade, consultar novamente, comparar fingerprint,
geração, grupo e restrições; só reutilizar se tudo corresponder. Não fazer
delete-all seguido de importação. [Apple: errSecDuplicateItem](https://developer.apple.com/documentation/security/errsecduplicateitem).

Usar uma fila/actor coordenador para a primeira importação. Se houver extensions
com acesso compartilhado, serialização apenas em memória de um processo não
basta: tratar concorrência entre processos e reconsultar após conflito. A escrita
de vários componentes não deve ser tratada como transação global automática.
Preparar a geração nova, verificar leitura/uso e depois ativá-la. Qualquer rollback
remove apenas itens criados por aquela operação, sem apagar chaves/certificados
usados pela geração anterior.

### Access groups, sincronização e acessibilidade

Manter o grupo padrão privado do app; adicionar `keychain-access-groups` e
entitlements apenas quando uma extension/app autorizada realmente precisar do
acesso. Compartilhar o grupo amplia o conjunto de processos que usam a identidade.
Assinatura e provisioning precisam conferir com os grupos escolhidos.
[Apple Platform Security: Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web).

Nas operações/classes que suportam sincronização, definir explicitamente
`kSecAttrSynchronizable=false` para persistência e buscas locais; não habilitar
iCloud Keychain nem usar uma busca ampla de sincronizáveis para contornar ausência.
Confirmar suporte de cada classe nas versões mínimas (certificados/chaves passaram
a ter sincronização em iOS 14). `ThisDeviceOnly` é incompatível com sincronização
habilitada. [Apple: kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable).

| Classe candidata | Decisão de produto necessária |
|---|---|
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Preferência proposta se todas as operações exigirem aparelho desbloqueado; não atende uso com tela bloqueada |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | Avaliar somente para background necessário após primeiro desbloqueio; amplia a disponibilidade enquanto bloqueado |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Exige passcode e aparelho desbloqueado; remoção/reset do passcode pode inutilizar os itens dessa classe |

Após reboot, antes do primeiro desbloqueio, não presumir disponibilidade para
nenhuma das escolhas acima. Aguardar/adiar com erro controlado; não retornar a
P12 em arquivo aberto ou a uma classe menos restritiva. `ThisDeviceOnly` restringe
migração/restauração para outro dispositivo; não torna a chave originada no Enclave.
[Restricting keychain item accessibility](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
e [classes e passcode na Apple Platform Security](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web).

Não impor biometria em cada handshake por padrão. Antes de usar flags de presença
do usuário, medir prompts, reconexões, background, disponibilidade e UX. A decisão
de autenticar usuário/transação é separada de disponibilizar uma chave shared para
TLS. Não combinar atributos de acesso incompatíveis nem presumir que uma flag
signifique sempre “um prompt por request”.

Não assumir que desinstalar apaga os itens: a Apple DTS descreve a sobrevivência
ao uninstall como detalhe de implementação, não contrato de lifecycle.
Definir reconciliação segura de itens existentes, atualizar sessão separadamente e
testar update, reinstalação, backup/restore no mesmo/outro dispositivo, mudança de
passcode, assinatura e entitlements. Não usar reinstalação como revogação; a
autoridade continua sendo a política no gateway.
[Apple DTS: Keychain após uninstall](https://developer.apple.com/forums/thread/36442).

## Keychain e Secure Enclave são propriedades distintas

**Uma chave compartilhada previamente gerada e distribuída em um PKCS#12 não se
transforma em uma chave originalmente gerada e não exportável no Secure Enclave
ao ser armazenada no Keychain.**

A proteção dos dados do Keychain controla armazenamento/acesso. A chave importada
continua tendo origem externa e cópias distribuídas. No caminho Security.framework
documentado pela Apple para Secure Enclave, as chaves são geradas nele, com o perfil
EC suportado; não se importam chaves RSA preexistentes do P12.
[Apple: Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).

Não transferir `privateKey.getEncoded()==null` do Android para uma garantia iOS.
Obter `SecIdentity`/`SecKey` também não prova não exportabilidade física. Uma chave
gerada por instalação no Secure Enclave exigiria emissão de certificado para sua
chave pública e outro protocolo de cadastro/provisionamento; seria outro modelo,
fora desta proposta compartilhada e sem implementação nesta tarefa.

## Networking existente, mTLS e pinning

Adicionar um provider de identidade e tratamento de client authentication ao
cliente **URLSession existente**, preservando camada de API, sessão, autorização,
retries e observabilidade. Não reconstruir o transporte apenas para adicionar mTLS.
A composição precisa integrar seu delegate de autenticação ao já existente, sem
suprimir trust evaluation ou pinning implementados por ele.

### Dois tipos de challenge, decisões distintas

| Challenge | Condições propostas para responder |
|---|---|
| `NSURLAuthenticationMethodClientCertificate` | Host próprio exato, HTTPS/porta permitida, identidade válida/acessível, sem ciclo de tentativas; obter `SecIdentity` |
| `NSURLAuthenticationMethodServerTrust` | Manter avaliação do servidor: cadeia, validade, hostname, trust policy, ATS e pinning do gateway |
| Outros tipos | Preservar a política do cliente existente; não oferecer a identidade mTLS a desafios genéricos |

No challenge cliente, construir
`URLCredential(identity:certificates:persistence:)` com a identidade recuperada.
`certificates` são **intermediárias** necessárias ao servidor; para a cadeia
direta leaf → CA do lab, normalmente `nil`, não a raiz inteira nem o leaf duplicado.
A documentação indica `.forSession` e esclarece que esse inicializador ignora o
parâmetro de persistência; ele não substitui armazenamento explícito no Keychain.
[Apple: URLCredential com SecIdentity](https://developer.apple.com/documentation/foundation/urlcredential/init(identity:certificates:persistence:)).

Projetar exatamente **uma chamada** ao completion handler em todos os caminhos,
inclusive erro, cancelamento e execução assíncrona. Em host não autorizado, chave
indisponível ou falha de autenticação, cancelar o challenge cliente; não deixar o
sistema escolher inadvertidamente outra identidade. Conferir `previousFailureCount`
e limitar repetição; um novo challenge legítimo de outra conexão não é sozinho
prova de ataque. Resolver login/MFA na camada de sessão, fora desse callback.
Os pontos de callback de sessão/tarefa devem seguir o tipo de challenge documentado.
[Apple: Handling an authentication challenge](https://developer.apple.com/documentation/foundation/handling-an-authentication-challenge).

Usar allowlist de hostname canônico exato, protocolo e porta, não `contains`/sufixo
sem validação. Revisar redirects para não reenviar bearer nem identidade a outro
origin; manter política segura de redirecionamento da aplicação. Reuso de conexões,
pooling e retomada TLS significam que não há necessariamente challenge por request.
A troca de geração precisa prever reconstrução/invalidação controlada de sessões
e conexões, sem fingir que mudar uma variável troca uma conexão TLS já estabelecida.

Background sessions e restauração do processo têm lifecycle próprio. Testar se
delegate/identidade estarão disponíveis quando o sistema precisar, com o grupo e
classe Keychain escolhidos; a identidade apenas em memória não resolve o reboot.
Background não autoriza desabilitar pinning ou exigir um prompt impossível de
mostrar. A proposta não declara esse cenário suportado antes dos testes.
[Apple: Downloading files in the background](https://developer.apple.com/documentation/foundation/downloading-files-in-the-background).

### Trust do servidor e SPKI compatível

Se a avaliação já for feita pelo sistema/ATS e pelo pinning existente, preservá-la.
Se houver avaliação manual, aplicar policy TLS de **servidor** com hostname
esperado e avaliar `SecTrust`; uma CA confiável sozinha não basta. Falha de trust
ou pin cancela. `URLCredential(trust:)` jamais deve aceitar qualquer servidor ou
contornar resultado negativo. Manter ATS e requisitos existentes, sem adicionar
exceção global para fazer o lab “funcionar”.
[Apple: manual server trust authentication](https://developer.apple.com/documentation/foundation/performing-manual-server-trust-authentication)
e [SecPolicyCreateSSL e hostname](https://developer.apple.com/documentation/security/secpolicycreatessl(_:_:)).

Definição comum às plataformas:

```text
pin = Base64(SHA-256(DER(SubjectPublicKeyInfo da chave pública do gateway)))
```

Conservar primary e backup, aceitando um deles **além** da validação TLS normal.
Certificado válido pela CA e com hostname correto, mas com outra SPKI, deve falhar.
Não usar hash do certificado inteiro, hash do módulo RSA ou bytes de chave brutos
como substituto. `SecKeyCopyExternalRepresentation` retorna PKCS#1 para RSA e
X9.63 para chave pública EC; esses formatos não são automaticamente DER SPKI.
[Formato de exportação Apple](https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:))
e [definição SPKI-SHA256-BASE64](https://developer.apple.com/documentation/bundleresources/information-property-list/nspinnedleafidentities/spki-sha256-base64).

Uma opção a validar no deployment target é pinning nativo ATS por domínio, com
`NSPinnedLeafIdentities` contendo primary e backup. A comparação do formato é
implementada pela plataforma. Não adicionar também pins de CA sem intenção:
quando ambas as listas são configuradas, ambas precisam casar. Isso continua
sendo pinning do certificado externo do gateway, não do serviço Spring interno.
[Apple: NSPinnedLeafIdentities](https://developer.apple.com/documentation/bundleresources/information-property-list/nspinnedleafidentities).

Se o app já faz pinning manual, preservar essa integração e usar implementação/
biblioteca X.509 revisada que extraia o DER completo de SubjectPublicKeyInfo do
certificado (AlgorithmIdentifier + BIT STRING). Não montar prefixos ASN.1 por
suposição ou assumir igualdade por apenas usar SHA-256. Comparar vetores públicos
RSA/EC entre iOS, `common/pki.py` e OpenSSL. Não foi escolhida nem validada biblioteca
iOS neste repo. Não há pseudocódigo Swift parcial apresentado como implementação.

O iPhone não usa o `adb reverse` do lab Android. A VM atual escuta em loopback.
Um futuro ensaio requer endpoint de teste acessível, DNS/SAN e política de confiança
da CA de laboratório planejados para iOS. Esta tarefa não abre portas nem muda
certificados. Não trocar esse requisito por hostname/trust permissivos.

## RASP / Application Shielding iOS

**iOS shielding/RASP: NOT IMPLEMENTED / NOT VALIDATED.**

DexGuard destina-se ao Android; iXGuard é o produto iOS da Guardsquare. O fabricante
anuncia proteção de código e controles de runtime. Isso descreve capacidade
comercial anunciada, não comprova produto instalado, licença, configuração ou
proteção eficaz deste projeto. Não há regras, comandos ou sintaxe iXGuard aqui.
[Guardsquare: iXGuard](https://www.guardsquare.com/ixguard).

Antes de integrar qualquer produto, registrar versão/licença, documentação oficial
daquela versão, compatibilidade com Xcode/Swift/Objective-C e bibliotecas usadas,
proteção realmente disponível para recurso P12/configuração/código e compatibilidade
com Keychain, Security.framework, callbacks TLS e pinning. Validar também assinatura,
distribuição, símbolos/diagnóstico e tratamento de segredos no pipeline.

Avaliar jailbreak, debugger, hooking/instrumentação (inclusive Frida), tampering,
repackaging, alteração do importador/trust/pinning, captura de P12/senha em memória
e uso indevido da identidade pelo próprio processo legítimo. São casos de teste,
não promessas de detecção. Proteção estática e de runtime são complementares: uma
representação protegida precisa tornar-se utilizável em execução. A distinção
entre essas camadas aparece na [descrição de Application Shielding do fabricante](https://www.guardsquare.com/mobile-application-shielding);
sua eficácia precisa ser medida na build adotada.

Definir política de reação antes do rollout:

- Graduar resposta ao risco e à confiança do sinal: restringir uma operação
  sensível, exigir recuperação segura ou bloquear conforme política aprovada.
- Medir falsos positivos, estabilidade, latência, consumo e impacto em login,
  handshakes e background, incluindo aparelhos suportados sem alterações hostis.
- Enviar somente telemetria necessária, sem P12, senha, private key, bearer ou
  segredo de MFA; prever suporte, recuperação e revisão dos casos legítimos.
- Nunca aceitar TLS sem validação, desativar pins ou oferecer credencial alternativa
  permissiva como mecanismo de recuperação.

Keychain não impede hooking; shielding não torna a chave impossível de extrair.
Não adicionar `X-RASP: true`, proof fake ou autenticação por booleano autodeclarado.
RASP local não é prova remota de integridade e não resulta automaticamente do mTLS.
Mecanismos de attestation, se futuramente adotados, exigirão protocolo e validação
próprios no servidor, fora desta tarefa.

## Rotação e riscos operacionais

Planejar `embedded-v1 → embedded-v2` sem alterar a implementação atual: novo par,
certificado e identificação dos itens, novo release; gateway admite ambas as
gerações por período definido; medir adoção por geração/plataforma; retirar v1.
Validade precisa comportar distribuição e adesão reais às atualizações. Um app
antigo continua contendo v1; nunca confiar só em header de versão enviado pelo app.

No iOS, a coexistência no Keychain requer localizar explicitamente v2, sem assumir
que a busca pelo “primeiro” certificado retorne a geração ativa. Preservar v1
durante transição planejada apenas enquanto ainda for autorizada; remover seus
itens com escopo preciso quando seguro. Rotação emergencial pode exigir retirada
imediata e interrupção de usuários. Retirar a geração afeta todas as instalações
dependentes dela, não um aparelho isolado.

Vazamento compromete toda a geração. Outra cópia da chave pode reutilizar um
bearer roubado quando a sessão está vinculada apenas ao fingerprint compartilhado,
como neste backend. Keychain, ThisDeviceOnly e shielding não tornam esse vínculo
individual. Limpar buffers de Swift/Data/provider é best effort; não prometer
zeroização de todas as cópias ou revogação apagando apenas dados do app.
O lifecycle completo, inclusive emissão e rollout multi-plataforma, continua pendente.

## Checklist iOS — NÃO EXECUTADO

Cada item abaixo precisa de evidência própria em aparelhos iOS físicos e versões
suportadas. Simulador pode auxiliar desenvolvimento, mas não prova comportamento
de Keychain/Secure Enclave, bloqueio, background ou proteção em aparelho real.

- [ ] **NÃO EXECUTADO:** primeiro uso, persistência e recuperação após novo processo;
  contador/instrumentação de teste demonstrando ausência de releitura do P12.
- [ ] **NÃO EXECUTADO:** P12 inválido/truncado, senha incorreta, nenhuma ou múltiplas
  identidades; falha sem substituir identidade anterior válida.
- [ ] **NÃO EXECUTADO:** certificado expirado, CA inesperada, usos/constraints
  incorretos, algoritmo/tamanho incompatível e chave que não corresponde ao certificado.
- [ ] **NÃO EXECUTADO:** importações concorrentes, duplicidade e recuperação de
  estado parcial; conferência dos atributos de chave/certificado e access group.
- [ ] **NÃO EXECUTADO:** client certificate correto, ausência e outro cliente
  (mesma CA fora da allowlist e CA não autorizada); enforcement real no gateway.
- [ ] **NÃO EXECUTADO:** pins principal/backup e SPKI fora dos pins com CA válida;
  vetores idênticos entre plataformas; hostname inválido, cadeia/validade inválidas.
- [ ] **NÃO EXECUTADO:** aparelho bloqueado, reboot antes/depois do primeiro unlock,
  passcode alterado/removido/resetado, requests e sessions em background.
- [ ] **NÃO EXECUTADO:** completion handler único, cancelamento, repetição de
  challenge, redirects para origin não permitido, conexão reutilizada e retomada TLS.
- [ ] **NÃO EXECUTADO:** atualização, reinstalação, backup/restore no mesmo/outro
  aparelho, mudança de assinatura/entitlements/access group; sincronização desabilitada.
- [ ] **NÃO EXECUTADO:** headers `X-Internal-MTLS-*` forjados com/sem certificado;
  backend recebe somente metadata reconstruída ou nenhuma request aceita.
- [ ] **NÃO EXECUTADO:** tentativa de acesso direto ao backend, inclusive com
  certificado mobile; recusa sem identidade autenticada do gateway.
- [ ] **NÃO EXECUTADO:** mTLS válido sem sessão e com bearer inválido; depois
  login/MFA, conta, expiração e logout; JWT real quando houver implementação Spring.
- [ ] **NÃO EXECUTADO:** duas instalações da mesma geração com mesmo fingerprint,
  comportamento com bearer roubado e eventual separação Android/iOS.
- [ ] **NÃO EXECUTADO:** extração estática da baseline iOS em ambiente autorizado,
  localização de P12/configuração, comparação de bytes e acesso ao contêiner,
  sem imprimir/expor secrets.
- [ ] **NÃO EXECUTADO:** build protegida, se houver produto/licença; testes estáticos
  e ataques de runtime autorizados, incluindo falsos positivos, performance e suporte.
- [ ] **NÃO EXECUTADO:** release v2, coexistência, ativação explícita, retirada de
  v1 com conexões/sessões em uso e recuperação dos usuários afetados.

As decisões ainda abertas são: versões mínimas iOS/Xcode; foreground/background
realmente necessário; classe de acesso e efeitos de passcode; grupos/entitlements;
formato PKCS#12; parser de certificado e mecanismo de pinning já usados pelo app;
geração comum ou separada por plataforma; e produto comercial/versionamento/licença.
Nenhuma delas exige alterar silenciosamente o lab Android para redigir esta proposta.
