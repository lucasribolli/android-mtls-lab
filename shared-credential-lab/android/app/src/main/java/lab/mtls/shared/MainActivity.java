package lab.mtls.shared;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;

public final class MainActivity extends Activity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final List<Button> buttons = new ArrayList<>();
    private SharedApi api;
    private LinearLayout layout;
    private EditText account, password, otp;
    private TextView status;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        api = new SharedApi(this);
        ScrollView scroll = new ScrollView(this);
        layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL);
        int padding = (int)(16 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding); scroll.addView(layout);
        setContentView(scroll);
        label("mTLS · credencial compartilhada", 23);
        TextView warning = label("RASP SIMULADO — sem detecção real de root/Frida.\nUma chave privada para todas as instalações.", 15);
        warning.setTextColor(0xff9c3010);
        account = input("Conta", InputType.TYPE_CLASS_TEXT);
        password = input("Senha", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        otp = input("TOTP (6 dígitos; aguarde novo código após cada login)", InputType.TYPE_CLASS_NUMBER);
        button("1. Receber chave via HTTPS + pinning", () -> {
            JSONObject credentials = credentialsOnUi();
            return () -> { api.provision(credentials); return "Credencial recebida e importada no Android Keystore."; };
        });
        button("2. Login/MFA por mTLS", () -> {
            JSONObject credentials = credentialsOnUi();
            return () -> { api.login(credentials); return "Sessão de usuário criada por mTLS."; };
        });
        button("3. Consultar conta", () -> () -> api.account().toString(2));
        button("Ver identidade mTLS (sem sessão)", () -> () -> api.identityOnly().toString(2));
        button("Sair da sessão", () -> () -> { api.logout(); return "Sessão encerrada."; });
        label("Diagnósticos — inicie o servidor com --diagnostics", 15);
        button("Pin principal (8544)", () -> () -> api.pinProbe(8544).toString());
        button("Pin de reserva (8546)", () -> () -> api.pinProbe(8546).toString());
        button("Rejeitar servidor sem pin (8545)", () -> () -> {
            try { api.pinProbe(8545); }
            catch (Exception expected) {
                Throwable cause = expected;
                while (cause != null) {
                    if (cause.getMessage() != null && cause.getMessage().toLowerCase(java.util.Locale.ROOT).contains("pin verification failed"))
                        return "PASSOU: cadeia válida da CA local rejeitada por PIN VERIFICATION FAILED.";
                    cause = cause.getCause();
                }
                throw expected; // Falha de rede/validade não comprova pinning.
            }
            throw new IllegalStateException("FALHOU: servidor sem pin foi aceito!");
        });
        button("Testar sem certificado", () -> () -> api.withoutIdentity().toString());
        button("Testar sem sessão", () -> () -> api.withoutSession().toString());
        status = label("Pronto. Receba a credencial para começar.", 14);
        status.setTextIsSelectable(true);
        refresh("Pronto.");
    }

    private TextView label(String text, int size) {
        TextView view = new TextView(this); view.setText(text); view.setTextSize(size);
        view.setPadding(0, 8, 0, 8); layout.addView(view); return view;
    }
    private EditText input(String hint, int type) {
        EditText view = new EditText(this); view.setHint(hint); view.setContentDescription(hint);
        view.setInputType(type); view.setSingleLine(true);
        view.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        layout.addView(view); return view;
    }
    private JSONObject credentialsOnUi() throws Exception {
        return SharedApi.credentials(account.getText().toString().trim(), password.getText().toString(), otp.getText().toString());
    }
    private interface Action { String run() throws Exception; }
    private interface Prepare { Action run() throws Exception; }
    private void button(String text, Prepare prepare) {
        Button button = new Button(this); button.setText(text); layout.addView(button); buttons.add(button);
        button.setOnClickListener(view -> {
            try {
                Action action = prepare.run();
                ((android.view.inputmethod.InputMethodManager)getSystemService(INPUT_METHOD_SERVICE))
                        .hideSoftInputFromWindow(view.getWindowToken(), 0);
                buttons.forEach(b -> b.setEnabled(false)); status.setText("Executando…");
                executor.execute(() -> {
                    String result;
                    try { result = action.run(); }
                    catch (Exception error) { result = "ERRO: " + error.getClass().getSimpleName() + ": " + error.getMessage(); }
                    final String message = result;
                    runOnUiThread(() -> {
                        if (isDestroyed()) return;
                        password.setText(""); otp.setText("");
                        buttons.forEach(b -> b.setEnabled(true)); refresh(message);
                        status.requestFocus();
                        ((ScrollView)layout.getParent()).post(() -> ((ScrollView)layout.getParent()).fullScroll(View.FOCUS_DOWN));
                    });
                });
            } catch (Exception error) { refresh("ERRO: " + error.getMessage()); }
        });
    }
    private void refresh(String message) {
        try {
            SharedIdentity identity = SharedIdentity.active(this);
            status.setText(message + "\n\n" + api.sessionDescription() + "\n\n"
                    + (identity == null ? "Sem credencial importada." : identity.description()));
        } catch (Exception error) { status.setText(message + "\nKeystore: " + error.getMessage()); }
    }
    @Override protected void onDestroy() { executor.shutdown(); super.onDestroy(); }
}
