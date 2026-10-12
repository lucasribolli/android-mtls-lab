package lab.mtls.embedded;

import android.content.Context;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public final class AndroidKeyStoreCredentialStore {
    private final KeyStore store;
    private final CredentialValidator validator;
    public AndroidKeyStoreCredentialStore(Context context) throws Exception {
        store = KeyStore.getInstance("AndroidKeyStore"); store.load(null);
        validator = new CredentialValidator(context);
    }
    public boolean containsAlias() throws Exception { return store.containsAlias(GeneratedCredential.KEYSTORE_ALIAS); }
    public MtlsCredential read() throws Exception {
        if (!containsAlias()) return null;
        PrivateKey key = (PrivateKey)store.getKey(GeneratedCredential.KEYSTORE_ALIAS, null);
        Certificate[] chain = store.getCertificateChain(GeneratedCredential.KEYSTORE_ALIAS);
        if (key == null || chain == null) throw new java.security.cert.CertificateException("Alias sem identidade completa.");
        return new MtlsCredential(GeneratedCredential.KEYSTORE_ALIAS, key,
                Arrays.copyOf(chain, chain.length, X509Certificate[].class));
    }
    void validate(MtlsCredential credential) throws Exception {
        validator.validate(credential.privateKey, credential.chain());
        if (info(credential).getOrigin() != KeyProperties.ORIGIN_IMPORTED)
            throw new java.security.cert.CertificateException("Origem da chave não é IMPORTED.");
        if (credential.privateKey.getEncoded() != null)
            throw new java.security.InvalidKeyException("Provider retornou chave exportável após importação.");
    }
    MtlsCredential importEntry(PrivateKey key, X509Certificate[] chain) throws Exception {
        validator.validate(key, chain);  // Validar ANTES de substituir qualquer entrada.
        if (!"RSA".equals(key.getAlgorithm())) throw new java.security.InvalidKeyException("Perfil não suportado.");
        KeyProtection protection = new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                // Conscrypt Android 10 prepara digest/padding antes da operação privada TLS.
                .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                                      KeyProperties.SIGNATURE_PADDING_RSA_PSS).build();
        store.setEntry(GeneratedCredential.KEYSTORE_ALIAS, new KeyStore.PrivateKeyEntry(key, chain), protection);
        try {
            MtlsCredential imported = read(); validate(imported); return imported;
        } catch (Exception error) {
            store.deleteEntry(GeneratedCredential.KEYSTORE_ALIAS); throw error;
        }
    }
    public KeyInfo info(MtlsCredential credential) throws Exception {
        return KeyFactory.getInstance(credential.privateKey.getAlgorithm(), "AndroidKeyStore")
                .getKeySpec(credential.privateKey, KeyInfo.class);
    }
}
