package lab.mtls.embedded;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Adiciona client authentication preservando o TrustManager fornecido pelo app. */
public final class MtlsSslContextConfigurer {
    private MtlsSslContextConfigurer() {}
    public static SSLContext configure(MtlsCredential credential, X509TrustManager existingTrustManager) throws Exception {
        if (existingTrustManager == null) throw new IllegalArgumentException("Informe o TrustManager existente.");
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(credential == null ? new KeyManager[0] : MtlsKeyManagerFactory.create(credential),
                     new TrustManager[]{existingTrustManager}, null);
        return context;
    }
}
