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

/** App comum: somente INTERNET. Chave da instalação criada no Android Keystore. */
public final class MainActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ArrayList<Button> buttons = new ArrayList<>();
    private TextView identityView;
    private TextView result;
    private EditText token;
    private Button enroll;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        int padding = (int) (18 * getResources().getDisplayMetrics().density);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, padding, padding, padding);
        content.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(padding, padding + insets.getSystemWindowInsetTop(),
                    padding, padding + insets.getSystemWindowInsetBottom());
            return insets;
        });
        content.addView(text("Banco Lab · identidade no aparelho", 23));
        content.addView(text("A chave privada é gerada nesta instalação. O cadastro usa HTTPS; "
                + "o acesso à conta exige mTLS. O token representa uma autorização prévia do banco.", 16));
        identityView = text("Carregando identidade…", 14);
        identityView.setTextIsSelectable(true);
        content.addView(identityView);
        addButton(content, "1. Gerar chave no aparelho", () -> {
            new BankIdentity().ensureKey();
            return "Chave pronta. O certificado local é provisório até o cadastro no banco.";
        });
        token = new EditText(this);
        token.setHint("Token de cadastro (gerado no servidor)");
        token.setSingleLine(true);
        token.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        token.setSaveEnabled(false);
        token.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO);
        content.addView(token);
        enroll = new Button(this);
        enroll.setText("2. Cadastrar identidade por HTTPS");
        enroll.setAllCaps(false);
        enroll.setOnClickListener(view -> {
            String value = token.getText().toString().trim();
            token.setText("");
            execute(() -> {
                BankApi.enroll(new BankIdentity(), value);
                return "Cadastro concluído. O certificado do banco foi associado à chave local. "
                        + "Agora acesse a conta por mTLS.";
            });
        });
        buttons.add(enroll);
        content.addView(enroll);
        addButton(content, "3. Acessar conta por mTLS", () -> BankApi.account(new BankIdentity()).toString(2));
        addButton(content, "Teste: acessar sem identidade", () -> {
            BankApi.account(null);
            return "ERRO: o servidor aceitou acesso sem certificado.";
        });
        result = text("O servidor precisa estar ativo. Cadastro: porta 8444. API: porta 8443.", 15);
        result.setTextIsSelectable(true);
        content.addView(result);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(content);
        setContentView(scroll);
        execute(() -> "Use os passos acima. Nenhum arquivo .p12 é necessário.");
    }

    private TextView text(String value, int size) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setPadding(0, 10, 0, 16);
        return view;
    }

    private void addButton(LinearLayout content, String label, Action action) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setOnClickListener(view -> execute(action));
        buttons.add(button);
        content.addView(button);
    }

    private interface Action { String run() throws Exception; }

    private void execute(Action action) {
        for (Button button : buttons) button.setEnabled(false);
        result.setText("Executando…");
        worker.execute(() -> {
            String message;
            String description = "Identidade indisponível.";
            boolean registered = false;
            try { message = action.run(); }
            catch (Exception error) {
                message = error.getClass().getSimpleName() + ": " + error.getMessage()
                        + "\nFalhas de rede não comprovam recusa de certificado; confira os logs do servidor.";
            }
            try {
                BankIdentity identity = new BankIdentity();
                description = identity.description();
                registered = identity.enrolled();
            } catch (Exception error) { description = error.toString(); }
            String finalMessage = message;
            String finalDescription = description;
            boolean finalRegistered = registered;
            runOnUiThread(() -> {
                if (isDestroyed()) return;
                result.setText(finalMessage);
                identityView.setText(finalDescription);
                for (Button button : buttons) button.setEnabled(true);
                enroll.setEnabled(!finalRegistered);
                token.setEnabled(!finalRegistered);
            });
        });
    }

    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
