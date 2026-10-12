# Arquitetura — Android → Gateway → Backend

## O que a fase 0 encontrou

O `shared-credential-lab` usa Python para gerar CA, pares do servidor e uma
identidade PKCS#12 compartilhada. O Android Java recebe P12/senha via HTTPS com
pinning após login/MFA e aprovação **simulada** de RASP; importa no AndroidKeyStore
e usa `X509ExtendedKeyManager` em um `SSLContext`. A autenticação de conta continua
separada do mTLS. Nesse lab o próprio servidor Python termina o mTLS do Android.

Foram lidos README principal, README/COMPARISON/VALIDATION do shared lab, fontes
Android, Manifest, Network Security Configuration, Gradle, servidor e scripts
antes da implementação. O resumo e o plano foram apresentados na conversa.

| Referência no shared lab | Reuso conceitual nesta pasta |
|---|---|
| `server/pki.py` | `common/pki.py`: certificados, PKCS#12 compatível e pins; adicionada PKI de serviços |
| `SharedIdentity.java` | provider, validator, store e key manager separados |
| `SharedApi.java` | transporte didático HttpsURLConnection, trust manager e pinning preservados |
| `server/auth.py` | `backend/auth.py`: senha/TOTP, prevenção de replay e limites locais |
| `server/lab.py` | dividido em `gateway/app.py` e `backend/app.py`; removido provisioning do desenho |
| scripts, Gradle e wrapper | cópias independentes com package, estado e portas próprios |

Os dois labs anteriores não foram modificados. O terceiro não importa código
nem compartilha segredos em runtime com eles.

## Fronteiras de confiança reais

```text
Android Java (APK com a shared identity)
  AndroidKeyStore [IMPORTED]
      │
      │ conexão 1: TLS >= 1.2, mTLS Android → edge
      │ valida CA + hostname + SPKI primary/backup do GATEWAY
      ▼
gateway/app.py — 127.0.0.1:8643, acessível ao Android por adb reverse
  termina TLS/mTLS externo
  valida client CA, validade, clientAuth, KeyUsage, BasicConstraints
  aplica allowlist por SHA-256 do certificado inteiro + serial + enabled
  recria metadata a partir do certificado do handshake
      │
      │ conexão 2: internal mTLS, CA DIFERENTE
      │ cliente = gateway-internal; servidor = backend-internal
      ▼
backend/app.py — 127.0.0.1:8650, sem adb reverse
  valida CA interna e fingerprint exato do SERVIÇO gateway
  só então aceita metadata da conexão 1
  valida sessão do USUÁRIO e atende /account
```

O backend recebe o handshake do **serviço gateway**, não o handshake original do
Android. Esse TLS interno não é transparência/passthrough: são certificados,
chaves, contextos TLS e sessões distintos. O Android não vê `backend-internal.crt`.
O gateway vê headers e body em claro no processo; comprometer o gateway quebra
a confiança na metadata que ele declara.

As duas aplicações são processos independentes, embora compartilhem usuário de
SO e diretório privado nesta VM. Isso demonstra autenticação entre serviços e
isolamento de rede, não isolamento contra root ou invasão do mesmo usuário Linux.
Em produção, separar identidades de workload, permissões, segredos e PKIs.

## Android: componentes para reaproveitar

| Componente Java | Função |
|---|---|
| `EmbeddedMtlsCredentialProvider` | prefere alias válido; só abre asset quando necessário; cacheia handle |
| `CredentialValidator` | valida identidade esperada, cadeia, usos, tempo e correspondência privada/pública |
| `AndroidKeyStoreCredentialStore` | importa `PrivateKeyEntry` com `KeyProtection`, recupera handle e `KeyInfo` |
| `MtlsCredential` | handle opaco da private key e cadeia pública |
| `MtlsKeyManagerFactory` | produz `X509ExtendedKeyManager` para client authentication |
| `MtlsSslContextConfigurer` | injeta KeyManagers e mantém o TrustManager recebido explicitamente |
| `DemoApi` | adaptação didática do transporte existente e sessão apenas em memória |
| `MainActivity` | UI e diagnósticos sem senhas/tokens/segredos de MFA |

O perfil desta v0.1 é RSA 2048. A geração falha explicitamente se o perfil for
alterado para algoritmo não implementado; o KeyManager seleciona conforme o
algoritmo real. Uma migração para EC exige perfil de importação/assinatura e testes,
não apenas mudar uma String. A chave importada tem finalidade SIGN, digests e
paddings necessários ao provider TLS do Android testado. Ela não é usada para
cifrar bodies manualmente. [KeyProtection documenta as restrições de uso na importação](https://developer.android.com/reference/android/security/keystore/KeyProtection).

O APK contém a versão original do P12 e a senha necessária ao carregamento.
`getEncoded()==null` no handle do Keystore não torna a chave original exclusiva
do hardware. `isInsideSecureHardware()` é diagnóstico local, sem prova remota.

## Gateway: autenticar e autorizar a geração

OpenSSL executa o handshake com `CERT_REQUIRED` e a CA externa; exige prova de
posse da private key. A aplicação também verifica validade, CA=false,
digitalSignature, EKU clientAuth e política por fingerprint/serial. Só então
encaminha a request. Um certificado da CA correta fora da allowlist recebe 403.
Ausência de certificado, CA inválida e expiração falham no TLS nos testes.

Não se usa Subject/CN enviado em header como autorização. A geração vem da
entrada autorizada na política, não de uma afirmação arbitrária do cliente.
Retirar uma geração bloqueia todos os seus usuários; nenhuma política aqui
consegue distinguir duas cópias da mesma chave.

Headers reconstruídos em cada request:

```text
X-Internal-MTLS-Verified: SUCCESS
X-Internal-MTLS-Fingerprint: <SHA-256 do certificado autenticado>
X-Internal-MTLS-Serial: <serial hexadecimal desse certificado>
X-Internal-MTLS-Version: <geração associada na allowlist>
```

O proxy cria um dicionário NOVO de headers. Não replica headers arbitrários
recebidos, incluindo esses quatro, qualquer casing/duplicação, `X-Forwarded-*`,
`Host` ou headers hop-by-hop. Só transporta `Authorization` validado como único,
Content-Type definido pelo proxy e a metadata recém-criada. O body é JSON
limitado, reserializado. Isso é proxy didático com rotas fixas, não proxy genérico.

O backend exige uma ocorrência de cada header, `SUCCESS`, fingerprint habilitado,
serial e versão consistentes. Antes disso, exige o certificado de serviço esperado
via mTLS interno. Um processo local com os quatro headers não ganha acesso.
Nem a credencial Android é aceita pela CA interna.

## Migration to Android + API Gateway + Spring Boot

### Android / OkHttp / Retrofit existentes

Reaproveitar provider, store e KeyManager; não portar toda a `DemoApi` para o app
do banco. A configuração de rede já existente deve fornecer o **mesmo**
`X509TrustManager` que implementa sua política atual. Não reconstruir trust a
partir de suposições nem trocar por um manager permissivo.

Pseudocódigo Java de integração; **não compilado contra OkHttp neste lab**:

```java
// existingClient e existingTrustManager vêm da composição de rede do app real.
MtlsCredential identity = credentialProvider.get(); // fora da thread de UI
SSLContext mtls = MtlsSslContextConfigurer.configure(identity, existingTrustManager);
OkHttpClient mtlsClient = existingClient.newBuilder()
    .sslSocketFactory(mtls.getSocketFactory(), existingTrustManager)
    .build();
// Reutilizar mtlsClient na composição Retrofit existente para os hosts do banco.
```

`newBuilder()` parte da configuração existente e a sobrecarga com dois argumentos
associa socket factory e TrustManager. A implementação oficial mantém no builder
interceptors, timeouts, autenticação e CertificatePinner.
[Referência no código do OkHttp](https://github.com/square/okhttp/blob/master/okhttp/src/commonJvmAndroid/kotlin/okhttp3/OkHttpClient.kt).

Confirmar isso na versão efetivamente usada pelo banco, incluindo NSC, cadeia,
HostnameVerifier, pins, connection specs e telemetria. Não remover o
CertificatePinner ou duplicar/reordenar interceptors às cegas. Logging deve
continuar redigindo Authorization, cookies, login e respostas de sessão. Limitar
o cliente com identidade mTLS aos hosts próprios aprovados; analisar redirects.
Criar/reutilizar o cliente uma vez, não abrir o P12 nem montar OkHttp por request.
A substituição de sockets precisa de testes para HTTP/2, pooling, retomada TLS,
renovação de sessão e comportamento offline da aplicação real.

Nesta v0.1 o transporte HttpsURLConnection abre conexões curtas para tornar os
handshakes observáveis, seguindo o lab anterior. Não é modelo de performance de
um app bancário. Não há teste de OkHttp/Retrofit real nesta entrega.

### API Gateway real

Configurar autenticação por certificado cliente, client CA, TLS mínimo/política
criptográfica, validade/clientAuth e allowlist de gerações. Exigir client auth nas
rotas protegidas sem caminho alternativo sem mTLS. Remover headers reservados
recebidos de qualquer fonte externa e inserir resultados do handshake autenticado.
Configuração exata depende do produto; não há arquivo NGINX/Envoy/WAF presumido.

Estabelecer rede privada e canal interno autenticado, preferencialmente mTLS de
serviços com identidade de workload. Usar certificado/policy do serviço gateway
separados da credencial Android. Controlar também listeners de health e rotas
administrativas. Definir como retirar gerações, expor métricas, preservar auditoria
e evitar confiar em headers forjados por proxies intermediários.

### Spring: consumir contexto do gateway e autenticar usuário

Pseudocódigo de integração Spring, não um projeto compilado. Os métodos de policy
e identidade de serviço abaixo são interfaces a implementar na infraestrutura:

```java
final class MtlsGatewayFilter extends OncePerRequestFilter {
    // gatewayTransport e credentialPolicy são dependências de infraestrutura.
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {
        // Identidade verificada do CANAL interno, nunca um header/IP autodeclarado.
        if (!gatewayTransport.isAuthenticatedExpectedGateway(request)) {
            response.sendError(403);
            return;
        }
        // exactlyOne rejeita ausente/duplicado e impõe limites de tamanho.
        String verified = exactlyOne(request, "X-Internal-MTLS-Verified");
        String fingerprint = exactlyOne(request, "X-Internal-MTLS-Fingerprint");
        String serial = exactlyOne(request, "X-Internal-MTLS-Serial");
        String version = exactlyOne(request, "X-Internal-MTLS-Version");
        if (!"SUCCESS".equals(verified)
                || !credentialPolicy.accepts(fingerprint, serial, version)) {
            response.sendError(403);
            return;
        }
        request.setAttribute("verifiedClientCredential",
                             new ClientCredential(fingerprint, serial, version));
        // Não criar Authentication de usuário a partir de mTLS shared.
        chain.doFilter(request, response); // JWT/sessão e autorização ainda rodam.
    }
}
```

**ALERTA: esse filtro só é seguro se (1) o backend não for publicamente acessível,
(2) o gateway remover headers reservados externos, (3) reinserir valores derivados
da autenticação real e (4) o canal Gateway → Spring for autenticado/confiável.**
Nenhum header isolado prova essas condições; loopback ou IP de origem sozinho
também não prova a identidade do serviço.

`gatewayTransport` pode receber do servidor/container o principal autenticado do
mTLS **interno** ou da camada de serviço confiável. Neste desenho, um atributo
`jakarta.servlet.request.X509Certificate`, se existir, corresponde ao **gateway**;
nunca deve ser interpretado como o certificado do Android. A metadata do Android
é uma declaração confiada ao edge depois de verificar esse caminho.

Registrar o filtro no SecurityFilterChain das rotas de negócio, sem registro duplo
automático no servlet container. Depois, manter Resource Server/JWT ou sessão do
app real. Para JWT: validar assinatura e algoritmos aceitos, issuer, audience,
expiração e demais claims requeridos, além de escopos/permissões por endpoint.
Não há um JWT validator caseiro neste lab. mTLS OK + bearer inválido continua 401;
JWT válido só permite o que a autorização de negócio autorizar.

Referências: [OncePerRequestFilter](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/filter/OncePerRequestFilter.html)
e [Spring Security Resource Server JWT](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html).

## Proteção comercial e lifecycle

DexGuard/RASP seria uma camada transversal sobre o app e sua inicialização,
provider/importer, pinning e uso da chave. A lógica mTLS não consulta `X-RASP`,
aprovação fake ou proof enviada ao servidor. A versão instalada na VM não possui
proteção comercial validada; veja [DEXGUARD.md](DEXGUARD.md).

Rotação planejada: manter `embedded-v1`/`mtls-embedded-v1`; produzir release N+1 com
novo par/novo certificado `embedded-v2` e alias próprio; gateway e backend aceitam
as duas entradas durante a janela; medir adoção por fingerprint; retirar v1 após
prazo definido. O backend não trata versão enviada pelo cliente como prova.
Não há geração/rollout dual automatizado nesta versão. Atualizar pins de servidor
e rotacionar credencial cliente são operações diferentes e devem ter planos próprios.
