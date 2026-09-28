package lab.mtls;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import org.json.JSONObject;

final class BankApi {
    static final String ENROLL = "https://localhost:8444/enroll";
    static final String ACCOUNT = "https://localhost:8443/account";

    static JSONObject enroll(BankIdentity identity, String token) throws Exception {
        if (identity.enrolled()) throw new IllegalStateException("Identidade já cadastrada. Use a API mTLS.");
        JSONObject response = request(ENROLL, null, token,
                new JSONObject().put("csr", identity.csr()));
        identity.install(response.getString("certificate"), response.getString("ca"));
        return response;
    }

    static JSONObject account(BankIdentity identity) throws Exception {
        if (identity != null && !identity.enrolled())
            throw new IllegalStateException("Cadastre a identidade antes de acessar a conta.");
        return request(ACCOUNT, identity, null, null);
    }

    private static JSONObject request(String url, BankIdentity identity, String token, JSONObject body) throws Exception {
        KeyManager[] managers = identity == null ? new KeyManager[0]
                : new KeyManager[]{new IdentityManager(identity.privateKey(), identity.chain())};
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(managers, null, null); // TrustManager e verificador de hostname padrão.
        HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
        connection.setSSLSocketFactory(tls.getSocketFactory());
        connection.setInstanceFollowRedirects(false); // Não reenviar token a outro destino.
        connection.setConnectTimeout(8000);
        connection.setReadTimeout(12000);
        connection.setRequestProperty("Connection", "close");
        try {
            if (body != null) {
                connection.setRequestMethod("POST");
                connection.setDoOutput(true);
                connection.setRequestProperty("Authorization", "Bearer " + token);
                connection.setRequestProperty("Content-Type", "application/json");
                byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
                connection.setFixedLengthStreamingMode(bytes.length);
                try (java.io.OutputStream out = connection.getOutputStream()) { out.write(bytes); }
            }
            int status = connection.getResponseCode();
            JSONObject response;
            try (InputStream in = status < 400 ? connection.getInputStream() : connection.getErrorStream()) {
                response = new JSONObject(read(in));
            }
            if (status != 200) throw new java.io.IOException("HTTP " + status + ": " + response.optString("erro"));
            return response;
        } finally { connection.disconnect(); }
    }

    private static String read(InputStream stream) throws Exception {
        if (stream == null) throw new java.io.IOException("Resposta vazia");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = stream.read(buffer)) != -1) {
            if (out.size() + count > 32768) throw new java.io.IOException("Resposta grande demais");
            out.write(buffer, 0, count);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static final class IdentityManager extends X509ExtendedKeyManager {
        private final PrivateKey key;
        private final X509Certificate[] chain;
        IdentityManager(PrivateKey key, X509Certificate[] chain) { this.key = key; this.chain = chain; }
        private boolean supports(String type, Principal[] issuers) {
            if (!"RSA".equalsIgnoreCase(type)) return false;
            if (issuers == null || issuers.length == 0) return true;
            for (Principal issuer : issuers) for (X509Certificate cert : chain)
                if (issuer.equals(cert.getIssuerX500Principal())) return true;
            return false;
        }
        @Override public String[] getClientAliases(String type, Principal[] issuers) {
            return supports(type, issuers) ? new String[]{BankIdentity.ALIAS} : null;
        }
        @Override public String chooseClientAlias(String[] types, Principal[] issuers, Socket socket) {
            if (types != null) for (String type : types) if (supports(type, issuers)) return BankIdentity.ALIAS;
            return null;
        }
        @Override public String chooseEngineClientAlias(String[] types, Principal[] issuers, SSLEngine engine) {
            return chooseClientAlias(types, issuers, null);
        }
        @Override public X509Certificate[] getCertificateChain(String alias) {
            return BankIdentity.ALIAS.equals(alias) ? chain.clone() : null;
        }
        @Override public PrivateKey getPrivateKey(String alias) {
            return BankIdentity.ALIAS.equals(alias) ? key : null;
        }
        @Override public String[] getServerAliases(String type, Principal[] issuers) { return null; }
        @Override public String chooseServerAlias(String type, Principal[] issuers, Socket socket) { return null; }
    }
}
