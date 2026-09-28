package lab.mtls;

import android.content.Context;
import java.util.Arrays;

/** Requer cadastro manual prévio com MFA; não embute nem recebe senhas/seeds TOTP. */
public final class EnrollmentTest {
    public void run(Context context) throws Exception {
        BankIdentity identity = BankIdentity.active(context);
        if (identity == null || !identity.enrolled()) throw new AssertionError("Cadastre pelo app antes do teste.");
        if (identity.privateKey().getEncoded() != null) throw new AssertionError("Chave privada exportável");
        if (!Arrays.equals(identity.chain()[0].getPublicKey().getEncoded(),
                BankIdentity.active(context).chain()[0].getPublicKey().getEncoded()))
            throw new AssertionError("Identidade não persistiu");
        BankApi bank = new BankApi(context);
        try {
            bank.withoutSession();
            throw new AssertionError("Conta aceita sem sessão");
        } catch (BankApi.HttpError expected) {
            if (expected.status != 401) throw expected;
        }
        try {
            bank.withoutIdentity();
            throw new AssertionError("Conta aceita sem certificado");
        } catch (javax.net.ssl.SSLException expected) { /* Rejeição no TLS. */ }
    }
}
