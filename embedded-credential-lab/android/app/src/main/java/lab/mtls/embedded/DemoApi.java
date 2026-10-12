package lab.mtls.embedded;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.json.JSONObject;

/** Transporte didático existente (HttpsURLConnection). Não requer substituir OkHttp em produção. */
final class DemoApi {
    static final String API = "https://localhost:8643";
    private final EmbeddedMtlsCredentialProvider credentials;
    private final X509TrustManager trustManager;
    private String session;
    private long expires;
    String pinStatus = "Not tested";
    String gatewayStatus = "Not tested";

    DemoApi(EmbeddedMtlsCredentialProvider credentials) throws Exception {
        this.credentials = credentials;
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore)null);  // Android Network Security Configuration, incluindo pins.
        X509TrustManager selected = null;
        for (TrustManager manager : factory.getTrustManagers())
            if (manager instanceof X509TrustManager) selected = (X509TrustManager)manager;
        if (selected == null) throw new IllegalStateException("TrustManager padrão não encontrado.");
        trustManager = selected;
    }
    String sessionStatus() { return session != null && System.currentTimeMillis() < expires ? "Authenticated" : "Not Authenticated"; }
    JSONObject identity() throws Exception {
        try {
            JSONObject result = request(API + "/identity", credentials.get(), null, null, false);
            gatewayStatus = "OK"; return result;
        } catch (Exception error) { gatewayStatus = "FAIL"; throw error; }
    }
    JSONObject spoofedHeaders() throws Exception { return request(API + "/identity", credentials.get(), null, null, true); }
    JSONObject withoutCertificate() throws Exception { return request(API + "/identity", null, null, null, true); }
    JSONObject withoutSession() throws Exception { return request(API + "/account", credentials.get(), null, null, false); }
    JSONObject invalidToken() throws Exception { return request(API + "/account", credentials.get(), "invalid.jwt.token", null, false); }
    void login(JSONObject body) throws Exception {
        session = null;
        JSONObject result = request(API + "/session", credentials.get(), null, body, false);
        session = result.getString("session_token");
        expires = (long)(result.getDouble("expires_at") * 1000);
        gatewayStatus = "OK";
    }
    JSONObject account() throws Exception {
        if (!"Authenticated".equals(sessionStatus())) throw new IllegalStateException("Faça login/MFA por mTLS.");
        try { return request(API + "/account", credentials.get(), session, null, false); }
        catch (HttpError error) { if (error.status == 401) session = null; throw error; }
    }
    void logout() throws Exception {
        try { request(API + "/logout", credentials.get(), session, new JSONObject(), false); }
        finally { session = null; }
    }
    JSONObject pin(int port) throws Exception {
        try {
            JSONObject result = request("https://localhost:" + port + "/health", null, null, null, false);
            pinStatus = "OK (" + port + ")"; return result;
        } catch (Exception error) { pinStatus = "FAIL (" + port + ")"; throw error; }
    }
    String rejectUnpinned() throws Exception {
        try { pin(8645); }
        catch (Exception error) {
            for (Throwable cause = error; cause != null; cause = cause.getCause()) {
                String message = cause.getMessage();
                if (message != null && message.toLowerCase(java.util.Locale.ROOT).contains("pin verification failed")) {
                    pinStatus = "OK — unpinned gateway rejected";
                    return "PASS: Pin verification failed (CA e hostname válidos, SPKI fora dos pins).";
                }
            }
            throw error; // Rede/validade não demonstram pinning.
        }
        throw new IllegalStateException("FAIL: gateway fora dos pins foi aceito.");
    }

    static final class HttpError extends java.io.IOException {
        final int status;
        HttpError(int status, String error) { super("HTTP " + status + ": " + error); this.status = status; }
    }
    private JSONObject request(String url, MtlsCredential credential, String bearer, JSONObject body, boolean spoof) throws Exception {
        HttpsURLConnection connection = (HttpsURLConnection)new URL(url).openConnection();
        connection.setSSLSocketFactory(MtlsSslContextConfigurer.configure(credential, trustManager).getSocketFactory());
        // HostnameVerifier padrão, CA e pinning permanecem ativos. Nenhum redirect com credenciais.
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(8000); connection.setReadTimeout(15000);
        connection.setRequestProperty("Connection", "close");
        try {
            if (bearer != null) connection.setRequestProperty("Authorization", "Bearer " + bearer);
            if (spoof) {
                connection.setRequestProperty("X-Internal-MTLS-Verified", "SUCCESS");
                connection.setRequestProperty("X-Internal-MTLS-Fingerprint", "fake");
                connection.setRequestProperty("X-Internal-MTLS-Version", "attacker-generation");
            }
            if (body != null) {
                byte[] data = body.toString().getBytes(StandardCharsets.UTF_8);
                connection.setRequestMethod("POST"); connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setFixedLengthStreamingMode(data.length);
                try (java.io.OutputStream out = connection.getOutputStream()) { out.write(data); }
                finally { java.util.Arrays.fill(data, (byte)0); }
            }
            int status = connection.getResponseCode();
            JSONObject result;
            try (InputStream in = status < 400 ? connection.getInputStream() : connection.getErrorStream()) {
                if (in == null) throw new java.io.IOException("Resposta vazia.");
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                byte[] buffer = new byte[2048]; int count;
                while ((count = in.read(buffer)) != -1) {
                    if (bytes.size() + count > 32768) throw new java.io.IOException("Resposta excede o limite.");
                    bytes.write(buffer, 0, count);
                }
                result = new JSONObject(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
            }
            if (status != 200) throw new HttpError(status, result.optString("error"));
            return result;
        } finally { connection.disconnect(); }
    }
}
