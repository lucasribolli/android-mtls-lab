package lab.mtls.embedded;

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
    private EmbeddedMtlsCredentialProvider provider;
    private DemoApi api;
    private LinearLayout layout;
    private EditText account, password, otp;
    private TextView status;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        ScrollView scroll = new ScrollView(this);
        layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL);
        int padding = (int)(16 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding); scroll.addView(layout); setContentView(scroll);
        label("mTLS Embedded Credential", 23);
        TextView protection = label("DEXGUARD: NOT AVAILABLE / NOT VALIDATED\nRASP: NOT ACTIVE / NOT VALIDATED\nFunctional unprotected build", 14);
        protection.setTextColor(0xff9c3010);
        try { provider = new EmbeddedMtlsCredentialProvider(this); api = new DemoApi(provider); }
        catch (Exception error) { label("Falha ao inicializar: " + error.getClass().getSimpleName(), 16); return; }
        label("Android → mTLS Gateway → internal mTLS → Backend\nO backend representa Spring e autentica o usuário.", 14);
        account = input("Conta", InputType.TYPE_CLASS_TEXT);
        password = input("Senha", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        otp = input("TOTP (6 dígitos)", InputType.TYPE_CLASS_NUMBER);
        button("Import / Check Credential", () -> () -> {
            provider.get(); return "Credential ready — " + provider.lastSource();
        });
        button("Test mTLS Gateway", () -> () -> api.identity().toString(2));
        button("Login via mTLS", () -> {
            JSONObject body = new JSONObject().put("account", account.getText().toString().trim())
                    .put("password", password.getText().toString()).put("otp", otp.getText().toString());
            return () -> { api.login(body); return "Sessão autenticada pelo backend interno."; };
        });
        button("Get Account", () -> () -> api.account().toString(2));
        button("Show mTLS Identity", () -> () -> api.identity().toString(2));
        button("Logout", () -> () -> { api.logout(); return "Sessão encerrada."; });
        button("Test Primary Pin", () -> () -> api.pin(8644).toString());
        button("Test Backup Pin", () -> () -> api.pin(8646).toString());
        button("Test Unpinned Server", () -> () -> api.rejectUnpinned());
        button("Test Spoofed Internal Headers", () -> () -> api.spoofedHeaders().toString(2));
        button("Test Without Client Certificate", () -> () -> api.withoutCertificate().toString());
        button("Test Without User Session", () -> () -> api.withoutSession().toString());
        status = label("Pronto. A importação ocorre uma vez; cada request usa o Keystore.", 14);
        status.setTextIsSelectable(true); refresh("Pronto.");
    }
    private TextView label(String text, int size) {
        TextView view = new TextView(this); view.setText(text); view.setTextSize(size);
        view.setPadding(0, 8, 0, 8); layout.addView(view); return view;
    }
    private EditText input(String hint, int type) {
        EditText view = new EditText(this); view.setHint(hint); view.setContentDescription(hint);
        view.setInputType(type); view.setSingleLine(true); view.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        layout.addView(view); return view;
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
                    String message;
                    try { message = action.run(); }
                    catch (Exception error) { message = "FAIL: " + error.getClass().getSimpleName() + ": " + error.getMessage(); }
                    final String result = message;
                    runOnUiThread(() -> {
                        if (isDestroyed()) return;
                        password.setText(""); otp.setText(""); buttons.forEach(b -> b.setEnabled(true)); refresh(result);
                        ((ScrollView)layout.getParent()).post(() -> ((ScrollView)layout.getParent()).fullScroll(View.FOCUS_DOWN));
                    });
                });
            } catch (Exception error) { refresh("FAIL: " + error.getClass().getSimpleName()); }
        });
    }
    private void refresh(String message) {
        try {
            String diagnostics = "Credential Source: EMBEDDED APK\nCredential Version: " + GeneratedCredential.CREDENTIAL_VERSION
                    + "\nKeystore Alias: " + GeneratedCredential.KEYSTORE_ALIAS + "\nAsset reads this process: " + provider.assetReadCount()
                    + "\nSSL Pinning: " + api.pinStatus + "\nmTLS Gateway: " + api.gatewayStatus
                    + "\nUser Session: " + api.sessionStatus();
            MtlsCredential credential = provider.store().read();
            if (credential == null) diagnostics += "\nAlias absent — not imported yet";
            else diagnostics += "\nKey Origin: IMPORTED (" + provider.store().info(credential).getOrigin() + ")"
                    + "\nHardware-backed reported locally: " + provider.store().info(credential).isInsideSecureHardware()
                    + "\nprivateKey.getEncoded() == null: " + (credential.privateKey.getEncoded() == null)
                    + "\nClient Certificate SHA-256:\n" + CredentialValidator.fingerprint(credential.chain()[0])
                    + "\nClient Certificate Expiration: " + credential.chain()[0].getNotAfter()
                    + "\nA cópia no APK continua existindo após a importação.";
            status.setText(message + "\n\n" + diagnostics);
        } catch (Exception error) { status.setText(message + "\nDiagnóstico indisponível: " + error.getClass().getSimpleName()); }
    }
    @Override protected void onDestroy() { executor.shutdown(); super.onDestroy(); }
}
