package lab.mtls;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

/** Credencial privada desta instalação. Não usa KeyChain nem permissões de administrador. */
final class BankIdentity {
    static final String ALIAS = "bank-client";
    private final KeyStore store;

    BankIdentity() throws Exception {
        store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
    }

    void ensureKey() throws Exception {
        if (store.containsAlias(ALIAS)) return;
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setKeySize(2048)
                // Conscrypt prepara digest/padding no TLS: autoriza a operação RSA
                // interna sem processá-los novamente (KeyGenParameterSpec.Builder).
                .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                                      KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setCertificateSubject(new X500Principal("CN=pending-enrollment"))
                .setCertificateNotBefore(new Date(System.currentTimeMillis() - 60000))
                .setCertificateNotAfter(new Date(System.currentTimeMillis() + 365L * 86400000))
                .build());
        generator.generateKeyPair(); // O certificado local é provisório, sem confiança do banco.
    }

    PrivateKey privateKey() throws Exception {
        return (PrivateKey) store.getKey(ALIAS, null); // Referência ao Keystore, não bytes da chave.
    }

    X509Certificate[] chain() throws Exception {
        Certificate[] chain = store.getCertificateChain(ALIAS);
        if (chain == null) return new X509Certificate[0];
        return Arrays.copyOf(chain, chain.length, X509Certificate[].class);
    }

    boolean enrolled() throws Exception {
        X509Certificate[] certs = chain();
        if (certs.length < 2) return false;
        try { certs[0].checkValidity(); }
        catch (java.security.cert.CertificateException invalid) { return false; }
        return certs[0].getExtendedKeyUsage() != null
                && certs[0].getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2");
    }

    String csr() throws Exception {
        ensureKey();
        return Pkcs10.create(chain()[0].getPublicKey(), privateKey());
    }

    void install(String certificatePem, String caPem) throws Exception {
        X509Certificate certificate = parse(certificatePem);
        X509Certificate ca = parse(caPem);
        certificate.checkValidity();
        ca.checkValidity();
        certificate.verify(ca.getPublicKey());
        if (certificate.getBasicConstraints() != -1 || ca.getBasicConstraints() < 0
                || !certificate.getIssuerX500Principal().equals(ca.getSubjectX500Principal())
                || certificate.getExtendedKeyUsage() == null
                || !certificate.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2")
                || certificate.getKeyUsage() == null || !certificate.getKeyUsage()[0]
                || !Arrays.equals(certificate.getPublicKey().getEncoded(), chain()[0].getPublicKey().getEncoded()))
            throw new IllegalArgumentException("Certificado incompatível com a chave ou com clientAuth.");
        // CA recebida pelo endpoint HTTPS autenticado do banco. Só substitui a cadeia pública.
        store.setKeyEntry(ALIAS, privateKey(), null, new Certificate[]{certificate, ca});
    }

    String description() throws Exception {
        if (!store.containsAlias(ALIAS)) return "Nenhuma chave criada nesta instalação.";
        KeyInfo info = KeyFactory.getInstance("RSA", "AndroidKeyStore")
                .getKeySpec(privateKey(), KeyInfo.class);
        String state = enrolled() ? "Identidade cadastrada\n" + chain()[0].getSubjectX500Principal()
                + "\nVálida até: " + chain()[0].getNotAfter() : "Chave local pronta; cadastro necessário.";
        return state + "\nChave exportável pela API: " + (privateKey().getEncoded() != null)
                + "\nHardware segundo o Android: " + info.isInsideSecureHardware()
                + "\nEssa informação local não é atestação para o banco.";
    }

    private static X509Certificate parse(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }
}
