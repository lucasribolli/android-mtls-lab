package lab.mtls.shared;

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

final class SharedApi {
    static final String BOOTSTRAP = "https://localhost:8544";
    static final String API = "https://localhost:8543";
    private final android.content.Context context;
    private String session;
    private long sessionExpires;
    private JSONObject grant;
    private JSONObject pending;

    SharedApi(android.content.Context context) { this.context = context.getApplicationContext(); }

    static JSONObject credentials(String account, String password, String otp) throws Exception {
        return new JSONObject().put("account", account).put("password", password).put("otp", otp);
    }

    String sessionDescription() {
        return session != null && System.currentTimeMillis() < sessionExpires
            ? "Sessão de usuário ativa (15 minutos)" : "Sessão de usuário desconectada";
    }

    void provision(JSONObject credentials) throws Exception {
        if (grant != null && System.currentTimeMillis() >= (long)(grant.getDouble("expires_at") * 1000)) {
            grant = null; pending = null;
        }
        if (grant == null) grant = request(BOOTSTRAP + "/bootstrap/login", null, null, credentials);
        try {
            String token = grant.getString("bootstrap_token");
            String challenge = grant.getString("challenge");
            if (pending == null) {
                JSONObject evidence = request(BOOTSTRAP + "/rasp/demo", null, token,
                        new JSONObject().put("challenge", challenge));
                pending = new JSONObject().put("challenge", challenge)
                        .put("rasp_evidence", evidence.getString("evidence"));
            }
            JSONObject bundle = request(BOOTSTRAP + "/provision", null, token, pending);
            SharedIdentity.importBundle(context, bundle);
            grant = null; pending = null; session = null;
        } catch (HttpError error) {
            if (error.status == 401 || error.status == 403 || error.status == 409) {
                grant = null; pending = null;
            }
            throw error;
        }
    }

    private SharedIdentity identity() throws Exception {
        SharedIdentity value = SharedIdentity.active(context);
        if (value == null) throw new IllegalStateException("Receba a credencial compartilhada primeiro.");
        return value;
    }

    void login(JSONObject credentials) throws Exception {
        session = null;
        JSONObject response = request(API + "/session", identity(), null, credentials);
        session = response.getString("session_token");
        sessionExpires = (long)(response.getDouble("expires_at") * 1000);
    }

    JSONObject account() throws Exception {
        if (session == null || System.currentTimeMillis() >= sessionExpires)
            throw new IllegalStateException("Faça login/MFA por mTLS para abrir uma sessão de usuário.");
        return request(API + "/account", identity(), session, null);
    }
    void logout() throws Exception {
        try { request(API + "/logout", identity(), session, new JSONObject()); }
        finally { session = null; }
    }
    JSONObject identityOnly() throws Exception { return request(API + "/identity", identity(), null, null); }
    JSONObject withoutSession() throws Exception { return request(API + "/account", identity(), null, null); }
    JSONObject withoutIdentity() throws Exception { return request(API + "/identity", null, null, null); }
    JSONObject pinProbe(int port) throws Exception { return request("https://localhost:" + port + "/health", null, null, null); }

    static final class HttpError extends java.io.IOException {
        final int status;
        HttpError(int status, String message) { super("HTTP " + status + ": " + message); this.status = status; }
    }

    private static JSONObject request(String url, SharedIdentity identity, String token, JSONObject body) throws Exception {
        KeyManager[] managers = identity == null ? new KeyManager[0]
                : new KeyManager[]{new IdentityManager(identity.privateKey(), identity.chain())};
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(managers, null, null); // TrustManager e verificador de hostname padrão.
        HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
        connection.setSSLSocketFactory(tls.getSocketFactory());
        connection.setInstanceFollowRedirects(false); // Não reenviar token a outro destino.
        connection.setConnectTimeout(8000);
        connection.setReadTimeout(45000);
        connection.setRequestProperty("Connection", "close");
        try {
            if (token != null) connection.setRequestProperty("Authorization", "Bearer " + token);
            if (body != null) {
                connection.setRequestMethod("POST");
                connection.setDoOutput(true);
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
            if (status != 200) throw new HttpError(status, response.optString("error"));
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
            return supports(type, issuers) ? new String[]{"client"} : null;
        }
        @Override public String chooseClientAlias(String[] types, Principal[] issuers, Socket socket) {
            if (types != null) for (String type : types) if (supports(type, issuers)) return "client";
            return null;
        }
        @Override public String chooseEngineClientAlias(String[] types, Principal[] issuers, SSLEngine engine) {
            return chooseClientAlias(types, issuers, null);
        }
        @Override public X509Certificate[] getCertificateChain(String alias) {
            return "client".equals(alias) ? chain.clone() : null;
        }
        @Override public PrivateKey getPrivateKey(String alias) {
            return "client".equals(alias) ? key : null;
        }
        @Override public String[] getServerAliases(String type, Principal[] issuers) { return null; }
        @Override public String chooseServerAlias(String type, Principal[] issuers, Socket socket) { return null; }
    }
}
