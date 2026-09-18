package lab.mtls;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.security.KeyChain;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

/** App didático: chave privada escolhida pelo usuário no KeyChain do Android. */
public final class MainActivity extends Activity {
    private static final int PICK_PKCS12 = 100;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private String alias;
    private TextView identity;
    private TextView result;
    private Button withCert;
    private Button withoutCert;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        if (state != null) alias = state.getString("alias");
        int padding = (int) (20 * getResources().getDisplayMetrics().density);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, padding, padding, padding);
        content.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(padding, padding + insets.getSystemWindowInsetTop(),
                    padding, padding + insets.getSystemWindowInsetBottom());
            return insets;
        });
        TextView title = text("mTLS: confiança nos dois sentidos", 24);
        content.addView(title);
        content.addView(text("Servidor: https://localhost:8443\n"
                + "Primeiro importe client.p12. Depois escolha o certificado e compare os dois testes. "
                + "O servidor exige uma identidade válida do cliente.", 16));
        Button install = button("1. Importar certificado (.p12)");
        install.setOnClickListener(view -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(intent, PICK_PKCS12);
        });
        content.addView(install);
        Button choose = button("2. Escolher identidade");
        choose.setOnClickListener(view -> KeyChain.choosePrivateKeyAlias(this,
                selected -> runOnUiThread(() -> {
                    alias = selected;
                    showIdentity();
                }), new String[]{"RSA", "EC"}, null, "localhost", 8443, alias));
        content.addView(choose);
        identity = text("", 16);
        showIdentity();
        content.addView(identity);
        withoutCert = button("3. Testar sem certificado: deve falhar");
        withoutCert.setOnClickListener(view -> test(false));
        content.addView(withoutCert);
        withCert = button("4. Testar mTLS: deve funcionar");
        withCert.setOnClickListener(view -> test(true));
        content.addView(withCert);
        result = text("Aguardando teste. O servidor precisa estar iniciado no Debian e a porta "
                + "8443 encaminhada pelo ADB.", 16);
        result.setTextIsSelectable(true);
        content.addView(result);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(content);
        setContentView(scroll);
    }

    private TextView text(String value, int size) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setPadding(0, 12, 0, 20);
        return view;
    }

    private Button button(String label) {
        Button view = new Button(this);
        view.setText(label);
        view.setAllCaps(false);
        return view;
    }

    private void showIdentity() {
        identity.setText(alias == null ? "Nenhuma identidade selecionada." : "Identidade: " + alias);
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        state.putString("alias", alias);
    }

    @Override protected void onActivityResult(int request, int code, Intent data) {
        super.onActivityResult(request, code, data);
        if (request != PICK_PKCS12 || code != RESULT_OK || data == null || data.getData() == null) return;
        worker.execute(() -> {
            try (InputStream stream = getContentResolver().openInputStream(data.getData())) {
                byte[] bundle = readBounded(stream, 1024 * 1024);
                runOnUiThread(() -> {
                    Intent install = KeyChain.createInstallIntent();
                    install.putExtra(KeyChain.EXTRA_PKCS12, bundle);
                    install.putExtra(KeyChain.EXTRA_NAME, "android-lab");
                    startActivity(install);
                    result.setText("Conclua a importação na tela do Android. Senha do laboratório: "
                            + "lab-android. Depois toque em Escolher identidade.");
                });
            } catch (Exception error) {
                showResult("Falha na importação: " + error.getMessage());
            }
        });
    }

    private static byte[] readBounded(InputStream stream, int limit) throws Exception {
        if (stream == null) throw new IllegalArgumentException("Arquivo indisponível");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = stream.read(buffer)) != -1) {
            if (bytes.size() + count > limit) throw new IllegalArgumentException("Conteúdo grande demais");
            bytes.write(buffer, 0, count);
        }
        return bytes.toByteArray();
    }

    private void test(boolean authenticated) {
        String chosen = alias;
        if (authenticated && chosen == null) {
            result.setText("Escolha a identidade antes de testar mTLS.");
            return;
        }
        withCert.setEnabled(false);
        withoutCert.setEnabled(false);
        result.setText("Conectando…");
        worker.execute(() -> {
            HttpsURLConnection connection = null;
            try {
                KeyManager[] managers = new KeyManager[0];
                if (authenticated) {
                    PrivateKey key = KeyChain.getPrivateKey(this, chosen);
                    X509Certificate[] chain = KeyChain.getCertificateChain(this, chosen);
                    if (key == null || chain == null || chain.length == 0)
                        throw new IllegalStateException("Identidade indisponível. Selecione novamente.");
                    managers = new KeyManager[]{new ClientIdentity(chosen, key, chain)};
                }
                SSLContext context = SSLContext.getInstance("TLS");
                // TrustManager padrão: respeita a configuração de confiança do app.
                context.init(managers, null, null);
                connection = (HttpsURLConnection) new URL("https://localhost:8443/").openConnection();
                connection.setSSLSocketFactory(context.getSocketFactory());
                // A verificação padrão de hostname permanece ativa.
                connection.setConnectTimeout(5000);
                connection.setReadTimeout(8000);
                connection.setRequestProperty("Connection", "close");
                int status = connection.getResponseCode();
                String body;
                try (InputStream stream = status < 400 ? connection.getInputStream() : connection.getErrorStream()) {
                    body = new String(readBounded(stream, 65536), StandardCharsets.UTF_8);
                }
                showResult("HTTP " + status + "\n" + body);
            } catch (Exception error) {
                showResult((authenticated ? "Falha no mTLS" : "Conexão sem certificado falhou")
                        + "\n" + error.getClass().getSimpleName() + ": " + error.getMessage()
                        + "\n\nSe aparecer conexão recusada ou tempo esgotado, confira o servidor e o ADB. "
                        + "Esses erros de rede, sozinhos, não comprovam uma recusa de certificado.");
            } finally {
                if (connection != null) connection.disconnect();
                runOnUiThread(() -> {
                    withCert.setEnabled(true);
                    withoutCert.setEnabled(true);
                });
            }
        });
    }

    private void showResult(String message) {
        runOnUiThread(() -> { if (!isDestroyed()) result.setText(message); });
    }

    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }

    private static final class ClientIdentity extends X509ExtendedKeyManager {
        private final String alias;
        private final PrivateKey key;
        private final X509Certificate[] chain;
        ClientIdentity(String alias, PrivateKey key, X509Certificate[] chain) {
            this.alias = alias;
            this.key = key;
            this.chain = chain.clone();
        }
        private boolean supports(String type) { return key.getAlgorithm().equalsIgnoreCase(type); }
        @Override public String[] getClientAliases(String type, Principal[] issuers) {
            return supports(type) ? new String[]{alias} : null;
        }
        @Override public String chooseClientAlias(String[] types, Principal[] issuers, Socket socket) {
            if (types != null) for (String type : types) if (supports(type)) return alias;
            return null;
        }
        @Override public String chooseEngineClientAlias(String[] types, Principal[] issuers, SSLEngine engine) {
            return chooseClientAlias(types, issuers, null);
        }
        @Override public X509Certificate[] getCertificateChain(String requested) {
            return alias.equals(requested) ? chain.clone() : null;
        }
        @Override public PrivateKey getPrivateKey(String requested) {
            return alias.equals(requested) ? key : null;
        }
        @Override public String[] getServerAliases(String type, Principal[] issuers) { return null; }
        @Override public String chooseServerAlias(String type, Principal[] issuers, Socket socket) { return null; }
    }
}
