package lab.mtls.shared;

import android.content.Context;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.UUID;
import org.json.JSONObject;

/** Importação real: a chave existiu no servidor e na memória do processo antes do Keystore. */
final class SharedIdentity {
    private static final String PREFS = "shared-v1";
    final String alias;
    private final KeyStore store;

    private SharedIdentity(String alias) throws Exception {
        this.alias = alias;
        store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
    }

    static SharedIdentity active(Context context) throws Exception {
        String alias = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("active", null);
        return alias == null ? null : new SharedIdentity(alias);
    }

    static void importBundle(Context context, JSONObject bundle) throws Exception {
        if (!"DEMO".equals(bundle.getString("rasp_mode"))
                || !"SHARED_ALL_INSTALLATIONS".equals(bundle.getString("credential_scope")))
            throw new IllegalArgumentException("Bundle incompatível com este laboratório.");
        byte[] bytes = Base64.decode(bundle.getString("p12_base64"), Base64.DEFAULT);
        char[] password = bundle.getString("p12_password").toCharArray();
        SharedIdentity imported = new SharedIdentity("shared-imported-" + UUID.randomUUID());
        boolean activated = false;
        try {
            KeyStore transport = KeyStore.getInstance("PKCS12");
            transport.load(new ByteArrayInputStream(bytes), password);
            String source = null;
            java.util.Enumeration<String> aliases = transport.aliases();
            while (aliases.hasMoreElements()) {
                String candidate = aliases.nextElement();
                if (transport.isKeyEntry(candidate)) {
                    if (source != null) throw new IllegalArgumentException("Mais de uma chave no P12.");
                    source = candidate;
                }
            }
            if (source == null) throw new IllegalArgumentException("P12 sem chave privada.");
            PrivateKey key = (PrivateKey) transport.getKey(source, password);
            Certificate[] chain = transport.getCertificateChain(source);
            if (chain == null || chain.length != 2) throw new IllegalArgumentException("Cadeia inesperada.");
            X509Certificate leaf = (X509Certificate) chain[0];
            X509Certificate ca = (X509Certificate) chain[1];
            X509Certificate trusted;
            try (java.io.InputStream in = context.getResources().openRawResource(lab.mtls.shared.R.raw.lab_ca)) {
                trusted = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
            }
            if (!Arrays.equals(trusted.getEncoded(), ca.getEncoded()))
                throw new IllegalArgumentException("CA inesperada no bundle.");
            ca.checkValidity(); leaf.checkValidity(); leaf.verify(ca.getPublicKey());
            if (leaf.getBasicConstraints() != -1 || ca.getBasicConstraints() < 0
                    || !"RSA".equals(key.getAlgorithm())
                    || !leaf.getIssuerX500Principal().equals(ca.getSubjectX500Principal())
                    || leaf.getKeyUsage() == null || !leaf.getKeyUsage()[0]
                    || leaf.getExtendedKeyUsage() == null
                    || !leaf.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2")
                    || !fingerprint(leaf).equals(bundle.getString("certificate_fingerprint")))
                throw new IllegalArgumentException("Certificado incompatível com clientAuth.");
            verifyPair(key, leaf);
            imported.store.setEntry(imported.alias, new KeyStore.PrivateKeyEntry(key, chain),
                    new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                        // Compatibilidade com as operações TLS do Conscrypt no Android 10.
                        .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256,
                                    KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                                              KeyProperties.SIGNATURE_PADDING_RSA_PSS).build());
            verifyPair(imported.privateKey(), leaf);
            KeyInfo info = imported.info();
            if (info.getOrigin() != KeyProperties.ORIGIN_IMPORTED || imported.privateKey().getEncoded() != null)
                throw new IllegalStateException("Origem ou proteção inesperada após importação.");
            SharedIdentity previous = active(context);
            if (!context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                    .putString("active", imported.alias).commit())
                throw new java.io.IOException("Falha ao persistir alias.");
            activated = true;
            if (previous != null) imported.store.deleteEntry(previous.alias);
        } finally {
            Arrays.fill(bytes, (byte) 0); Arrays.fill(password, '\0');
            bundle.remove("p12_base64"); bundle.remove("p12_password");
            // Best effort: Strings/objetos internos do provider não permitem zeragem garantida.
            if (!activated) imported.store.deleteEntry(imported.alias);
        }
    }

    private static void verifyPair(PrivateKey key, X509Certificate cert) throws Exception {
        byte[] challenge = new byte[32]; new SecureRandom().nextBytes(challenge);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key); signer.update(challenge);
        byte[] signature = signer.sign();
        signer.initVerify(cert.getPublicKey()); signer.update(challenge);
        if (!signer.verify(signature)) throw new IllegalArgumentException("Chave e certificado não correspondem.");
    }

    PrivateKey privateKey() throws Exception { return (PrivateKey) store.getKey(alias, null); }
    X509Certificate[] chain() throws Exception {
        Certificate[] certs = store.getCertificateChain(alias);
        if (certs == null) throw new IllegalStateException("Credencial não encontrada no Keystore.");
        return Arrays.copyOf(certs, certs.length, X509Certificate[].class);
    }
    private KeyInfo info() throws Exception {
        return KeyFactory.getInstance("RSA", "AndroidKeyStore").getKeySpec(privateKey(), KeyInfo.class);
    }
    static String fingerprint(X509Certificate cert) throws Exception {
        StringBuilder hex = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()))
            hex.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return hex.toString();
    }
    String description() throws Exception {
        return "Origem: IMPORTED (" + info().getOrigin() + ")\nHardware informado localmente: "
                + info().isInsideSecureHardware() + "\nExportável pela API após importação: "
                + (privateKey().getEncoded() != null) + "\nValidade: " + chain()[0].getNotAfter()
                + "\nSHA-256 do certificado compartilhado:\n" + fingerprint(chain()[0])
                + "\nA chave também existe no servidor e nas outras instalações.";
    }
}
