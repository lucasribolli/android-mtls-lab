package lab.mtls.embedded;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

public final class MtlsKeyManagerFactory {
    private MtlsKeyManagerFactory() {}
    public static KeyManager[] create(MtlsCredential credential) { return new KeyManager[]{new Manager(credential)}; }
    private static final class Manager extends X509ExtendedKeyManager {
        private final MtlsCredential credential;
        Manager(MtlsCredential credential) { this.credential = credential; }
        private boolean supports(String type, Principal[] issuers) {
            if (!credential.privateKey.getAlgorithm().equalsIgnoreCase(type)) return false;
            if (issuers == null || issuers.length == 0) return true;
            for (Principal issuer : issuers) for (X509Certificate cert : credential.chain())
                if (issuer.equals(cert.getIssuerX500Principal())) return true;
            return false;
        }
        @Override public String[] getClientAliases(String type, Principal[] issuers) {
            return supports(type, issuers) ? new String[]{credential.alias} : null;
        }
        @Override public String chooseClientAlias(String[] types, Principal[] issuers, Socket socket) {
            if (types != null) for (String type : types) if (supports(type, issuers)) return credential.alias;
            return null;
        }
        @Override public String chooseEngineClientAlias(String[] types, Principal[] issuers, SSLEngine engine) {
            return chooseClientAlias(types, issuers, null);
        }
        @Override public PrivateKey getPrivateKey(String alias) { return credential.alias.equals(alias) ? credential.privateKey : null; }
        @Override public X509Certificate[] getCertificateChain(String alias) { return credential.alias.equals(alias) ? credential.chain() : null; }
        @Override public String[] getServerAliases(String type, Principal[] issuers) { return null; }
        @Override public String chooseServerAlias(String type, Principal[] issuers, Socket socket) { return null; }
    }
}
