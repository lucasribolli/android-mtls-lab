package lab.mtls.embedded;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/** Referência opaca do AndroidKeyStore e cadeia pública; não contém P12/senha. */
public final class MtlsCredential {
    public final String alias;
    public final PrivateKey privateKey;
    private final X509Certificate[] certificates;
    MtlsCredential(String alias, PrivateKey key, X509Certificate[] chain) {
        this.alias = alias; privateKey = key; certificates = chain.clone();
    }
    public X509Certificate[] chain() { return certificates.clone(); }
}
