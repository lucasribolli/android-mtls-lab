package lab.mtls.embedded;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.security.keystore.KeyProperties;
import java.io.IOException;
import org.json.JSONObject;

/** Testes executados no UID do app via Instrumentation pública, nunca no APK normal. */
public final class EmbeddedTestRunner extends Instrumentation {
    private String mode;
    @Override public void onCreate(Bundle args) {
        super.onCreate(args); mode = args.getString("mode", "network"); start();
    }
    private static void check(boolean condition, String description) {
        if (!condition) throw new AssertionError(description);
    }
    private interface Operation { void run() throws Exception; }
    private static void unauthorized(Operation action) throws Exception {
        try { action.run(); }
        catch (DemoApi.HttpError expected) { check(expected.status == 401, "Esperado HTTP 401"); return; }
        throw new AssertionError("Conta autorizada sem sessão válida");
    }
    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            AndroidKeyStoreCredentialStore store = new AndroidKeyStoreCredentialStore(getTargetContext());
            if ("first".equals(mode) || "reinstall".equals(mode)) {
                check(!store.containsAlias(), "Alias deveria estar ausente antes da primeira importação/reinstalação");
                EmbeddedMtlsCredentialProvider provider = new EmbeddedMtlsCredentialProvider(getTargetContext());
                MtlsCredential credential = provider.get(); provider.get();
                check(store.containsAlias(), "Alias não persistiu");
                check(provider.assetReadCount() == 1, "Asset deve ser aberto uma única vez");
                check(credential.privateKey.getEncoded() == null, "Chave exportável pela API");
                check(store.info(credential).getOrigin() == KeyProperties.ORIGIN_IMPORTED, "Origem não é IMPORTED");
                check(CredentialValidator.fingerprint(credential.chain()[0]).equals(GeneratedCredential.EXPECTED_FINGERPRINT), "Fingerprint incorreto");
                result.putString("stream", "\nPASS " + mode + ": absent -> imported -> present; asset reads=1; encoded=null; origin=IMPORTED; fingerprint="
                        + GeneratedCredential.EXPECTED_FINGERPRINT + "; hardware locally reported=" + store.info(credential).isInsideSecureHardware() + "\n");
            } else {
                // Novo processo: falhar o teste se tentar abrir novamente o asset.
                EmbeddedMtlsCredentialProvider provider = new EmbeddedMtlsCredentialProvider(getTargetContext(), () -> {
                    throw new IOException("TEST FAILURE: asset must not be reopened after process restart");
                });
                MtlsCredential credential = provider.get();
                check(provider.assetReadCount() == 0, "Asset relido após restart");
                check(credential.privateKey.getEncoded() == null, "Chave exportável");
                DemoApi api = new DemoApi(provider);
                JSONObject identity = api.identity();
                check(identity.getString("client_fingerprint").equals(GeneratedCredential.EXPECTED_FINGERPRINT), "Gateway recebeu outra identidade");
                if ("network".equals(mode)) {
                    api.pin(8644); api.pin(8646); api.rejectUnpinned();
                    check(api.spoofedHeaders().getString("client_fingerprint").equals(GeneratedCredential.EXPECTED_FINGERPRINT), "Spoof aceito");
                    unauthorized(() -> api.withoutSession()); unauthorized(() -> api.invalidToken());
                    boolean rejected = false;
                    try { api.withoutCertificate(); }
                    catch (javax.net.ssl.SSLException expected) { rejected = true; }
                    check(rejected, "mTLS aceitou ausência de certificado");
                } else check("persist".equals(mode), "Modo de teste desconhecido");
                result.putString("stream", "\nPASS " + mode + ": persisted Keystore; asset reads=0; mTLS gateway/internal boundary verified; fingerprint="
                        + GeneratedCredential.EXPECTED_FINGERPRINT + ("network".equals(mode)
                        ? "; primary/backup pins OK; unpinned rejected; spoof overwritten; absent/invalid session 401; no certificate rejected" : "") + "\n");
            }
            finish(Activity.RESULT_OK, result);
        } catch (Throwable error) {
            // Não imprimir corpos de resposta, senhas, tokens nem objetos criptográficos.
            result.putString("stream", "\nFAIL " + mode + ": " + error.getClass().getSimpleName() + ": " + error.getMessage() + "\n");
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
