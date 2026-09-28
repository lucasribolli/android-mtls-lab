package lab.mtls;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
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
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.json.JSONArray;

/** Chave da instalação, acessível somente pelo UID do app. Não usa KeyChain. */
final class BankIdentity {
    private static final String PREFS = "bank-v3";
    final String alias;
    private final KeyStore store;
    private final Context context;

    private BankIdentity(Context context, String alias) throws Exception {
        this.context = context.getApplicationContext();
        this.alias = alias;
        store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
    }

    static BankIdentity active(Context context) throws Exception {
        String alias = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("active", null);
        return alias == null ? null : new BankIdentity(context, alias);
    }

    static BankIdentity generate(Context context, byte[] challenge) throws Exception {
        if (challenge.length != 32) throw new IllegalArgumentException("Challenge deve ter 32 bytes.");
        BankIdentity identity = new BankIdentity(context, "bank-attested-" + UUID.randomUUID());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        generator.initialize(new KeyGenParameterSpec.Builder(identity.alias, KeyProperties.PURPOSE_SIGN)
                .setKeySize(2048)
                .setAttestationChallenge(challenge)
                // Conscrypt/Android 10 prepara o digest e o padding antes da operação privada.
                .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                                      KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setCertificateSubject(new X500Principal("CN=pending-enrollment"))
                .setCertificateNotBefore(new Date(System.currentTimeMillis() - 60000))
                .setCertificateNotAfter(new Date(System.currentTimeMillis() + 365L * 86400000))
                .build());
        generator.generateKeyPair();
        return identity;
    }

    PrivateKey privateKey() throws Exception {
        return (PrivateKey) store.getKey(alias, null); // Referência opaca, nunca bytes privados.
    }

    X509Certificate[] chain() throws Exception {
        Certificate[] chain = store.getCertificateChain(alias);
        return chain == null ? new X509Certificate[0] : Arrays.copyOf(chain, chain.length, X509Certificate[].class);
    }

    JSONArray attestationChain() throws Exception {
        JSONArray result = new JSONArray();
        for (X509Certificate certificate : chain()) {
            result.put("-----BEGIN CERTIFICATE-----\n"
                    + Base64.encodeToString(certificate.getEncoded(), Base64.NO_WRAP)
                    + "\n-----END CERTIFICATE-----\n");
        }
        return result;
    }

    boolean enrolled() throws Exception {
        X509Certificate[] certs = chain();
        if (certs.length < 2) return false;
        try { certs[0].checkValidity(); }
        catch (java.security.cert.CertificateException invalid) { return false; }
        return certs[0].getExtendedKeyUsage() != null
                && certs[0].getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2");
    }

    String csr() throws Exception { return Pkcs10.create(chain()[0].getPublicKey(), privateKey()); }

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
            throw new IllegalArgumentException("Certificado incompatível com a chave ou clientAuth.");
        // Só a cadeia pública é substituída. A chave continua no Keystore.
        store.setKeyEntry(alias, privateKey(), null, new Certificate[]{certificate, ca});
    }

    void activate() throws Exception {
        if (!enrolled()) throw new IllegalStateException("Instale o certificado do banco primeiro.");
        if (!context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("active", alias).commit())
            throw new java.io.IOException("Não foi possível persistir o alias ativo.");
    }

    void discardPending() throws Exception {
        String active = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("active", null);
        if (!alias.equals(active)) store.deleteEntry(alias);
    }

    String description() throws Exception {
        KeyInfo info = KeyFactory.getInstance("RSA", "AndroidKeyStore").getKeySpec(privateKey(), KeyInfo.class);
        return (enrolled() ? "Identidade mTLS cadastrada" : "Certificado expirado: novo cadastro necessário")
                + "\n" + chain()[0].getSubjectX500Principal()
                + "\nValidade: " + chain()[0].getNotAfter()
                + "\nChave exportável pela API: " + (privateKey().getEncoded() != null)
                + "\nHardware informado localmente: " + info.isInsideSecureHardware();
    }

    private static X509Certificate parse(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }
}
