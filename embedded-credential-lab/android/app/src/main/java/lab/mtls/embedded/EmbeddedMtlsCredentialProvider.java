package lab.mtls.embedded;

import android.content.Context;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

/** Origem APK. Sem provisioning HTTP e sem dependência de API RASP simulada. */
public final class EmbeddedMtlsCredentialProvider {
    public interface AssetSource { InputStream open() throws IOException; }
    private final AssetSource source;
    private final AndroidKeyStoreCredentialStore store;
    private MtlsCredential cached;
    private int assetReads;
    private String lastSource = "Not initialized";

    public EmbeddedMtlsCredentialProvider(Context context) throws Exception {
        this(context, () -> context.getApplicationContext().getAssets().open("mtls/client.p12"));
    }
    // Ponto de injeção para testar a ausência de releitura; nenhum arquivo extra é persistido.
    EmbeddedMtlsCredentialProvider(Context context, AssetSource source) throws Exception {
        this.source = source; store = new AndroidKeyStoreCredentialStore(context);
    }
    public synchronized MtlsCredential get() throws Exception {
        if (cached != null) {
            for (X509Certificate cert : cached.chain()) cert.checkValidity();
            return cached;
        }
        MtlsCredential existing = store.read();
        if (existing != null) {
            try {
                store.validate(existing); cached = existing; lastSource = "AndroidKeyStore (asset not read)"; return existing;
            } catch (java.security.cert.CertificateException invalid) {
                // Ex.: certificado antigo após reinstalação de uma geração de laboratório.
                // O novo asset será validado integralmente antes de substituir o alias.
            }
        }
        byte[] buffer = new byte[32768];
        char[] password = GeneratedCredential.password();
        try {
            int size = 0;
            assetReads++;
            try (InputStream in = source.open()) {
                int count;
                while ((count = in.read(buffer, size, buffer.length - size)) != -1) {
                    size += count;
                    if (size == buffer.length) throw new IOException("P12 excede limite do laboratório.");
                }
            }
            KeyStore transport = KeyStore.getInstance("PKCS12");
            transport.load(new ByteArrayInputStream(buffer, 0, size), password);
            String alias = null;
            Enumeration<String> aliases = transport.aliases();
            while (aliases.hasMoreElements()) {
                String name = aliases.nextElement();
                if (transport.isKeyEntry(name)) {
                    if (alias != null) throw new java.security.KeyStoreException("P12 contém mais de uma chave.");
                    alias = name;
                }
            }
            if (alias == null) throw new java.security.KeyStoreException("P12 sem private key entry.");
            KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password);
            KeyStore.Entry entry;
            try { entry = transport.getEntry(alias, protection); }
            finally { protection.destroy(); }
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) throw new java.security.KeyStoreException("Entrada não é private key.");
            KeyStore.PrivateKeyEntry privateEntry = (KeyStore.PrivateKeyEntry)entry;
            Certificate[] chain = privateEntry.getCertificateChain();
            cached = store.importEntry(privateEntry.getPrivateKey(), Arrays.copyOf(chain, chain.length, X509Certificate[].class));
            lastSource = "APK asset imported once";
            return cached;
        } finally {
            Arrays.fill(buffer, (byte)0); Arrays.fill(password, '\0');
            // Best effort: o provider/VM pode manter Strings e cópias internas.
        }
    }
    public synchronized int assetReadCount() { return assetReads; }
    public synchronized String lastSource() { return lastSource; }
    public AndroidKeyStoreCredentialStore store() { return store; }
}
