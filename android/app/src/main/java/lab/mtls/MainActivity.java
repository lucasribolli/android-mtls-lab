package lab.mtls;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;

/** App comum com INTERNET: cadastro atestado, sessão e operações mTLS. */
public final class MainActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ArrayList<Button> buttons = new ArrayList<>();
    private TextView identityView, result;
    private EditText account, password, otp;
    private BankApi bank;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        bank = new BankApi(this);
        int padding = (int)(16 * getResources().getDisplayMetrics().density);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, padding, padding, padding);
        content.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(padding, padding + insets.getSystemWindowInsetTop(),
                    padding, padding + insets.getSystemWindowInsetBottom());
            return insets;
        });
        content.addView(text("Banco Lab · atestação + mTLS", 22));
        content.addView(text("Cadastro: senha e TOTP → chave no Keystore → atestação verificada pelo banco. "
                + "Depois, entre por mTLS para criar uma sessão de usuário.", 14));
        identityView = text("Carregando…", 13);
        content.addView(identityView);
        account = field(content, "Conta", InputType.TYPE_CLASS_TEXT);
        password = field(content, "Senha", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        otp = field(content, "Código TOTP (6 dígitos)", InputType.TYPE_CLASS_NUMBER);
        otp.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(6)});
        addCredentialsButton(content, "1. Cadastrar / retomar cadastro", true);
        addCredentialsButton(content, "2. Entrar por mTLS", false);
        addButton(content, "3. Consultar conta", () -> bank.account().toString(2));
        addButton(content, "4. Renovar certificado por mTLS", () -> {
            bank.renew();
            return "Certificado renovado. A chave privada e a sessão de usuário foram preservadas.";
        });
        addButton(content, "Sair da sessão", () -> {
            bank.logout();
            return "Sessão encerrada. A identidade mTLS continua instalada.";
        });
        addButton(content, "Teste: mTLS sem sessão", () -> bank.withoutSession().toString(2));
        addButton(content, "Teste: sem certificado mTLS", () -> bank.withoutIdentity().toString(2));
        result = text("Servidor: HTTPS 8444 e mTLS 8443. Use um novo TOTP em cada login.", 14);
        result.setTextIsSelectable(true);
        content.addView(result);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(content);
        setContentView(scroll);
        execute(() -> "O cadastro não cria uma sessão. Após cadastrar, aguarde o próximo código TOTP e entre.");
    }

    private EditText field(LinearLayout content, String hint, int type) {
        EditText field = new EditText(this);
        field.setHint(hint);
        field.setInputType(type);
        field.setSingleLine(true);
        field.setSaveEnabled(false);
        field.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO);
        content.addView(field);
        return field;
    }

    private void addCredentialsButton(LinearLayout content, String label, boolean enrollment) {
        Button button = button(content, label);
        button.setOnClickListener(view -> {
            try {
                JSONObject credentials = BankApi.credentials(account.getText().toString().trim(),
                        password.getText().toString(), otp.getText().toString().trim());
                password.setText("");
                otp.setText("");
                ((android.view.inputmethod.InputMethodManager)getSystemService(INPUT_METHOD_SERVICE))
                        .hideSoftInputFromWindow(otp.getWindowToken(), 0);
                execute(() -> {
                    if (enrollment) {
                        bank.enroll(credentials);
                        return "Atestação aprovada e certificado instalado. Agora entre por mTLS, com um novo TOTP.";
                    }
                    bank.login(credentials);
                    return "Login/MFA confirmado por mTLS. Sessão de usuário criada por 15 minutos.";
                });
            } catch (Exception error) { result.setText(error.getMessage()); }
        });
    }

    private TextView text(String value, int size) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setPadding(0, 6, 0, 8);
        return view;
    }

    private Button button(LinearLayout content, String label) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        buttons.add(button);
        content.addView(button);
        return button;
    }

    private void addButton(LinearLayout content, String label, Action action) {
        button(content, label).setOnClickListener(view -> execute(action));
    }

    private interface Action { String run() throws Exception; }

    private void execute(Action action) {
        for (Button button : buttons) button.setEnabled(false);
        result.setText("Executando…");
        worker.execute(() -> {
            String message;
            String description = "Identidade indisponível.";
            try { message = action.run(); }
            catch (Exception error) { message = error.getClass().getSimpleName() + ": " + error.getMessage(); }
            try {
                BankIdentity identity = BankIdentity.active(this);
                description = (identity == null ? "Sem identidade atestada. Faça o cadastro." : identity.description())
                        + "\n" + bank.sessionDescription();
            } catch (Exception error) { description = error.toString(); }
            String finalMessage = message;
            String finalDescription = description;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                result.setText(finalMessage);
                identityView.setText(finalDescription);
                for (Button button : buttons) button.setEnabled(true);
            });
        });
    }

    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy(); // Sessão só em memória; não é gravada nas preferências.
    }
}
