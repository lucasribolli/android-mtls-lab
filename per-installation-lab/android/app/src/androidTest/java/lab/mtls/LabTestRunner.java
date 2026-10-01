package lab.mtls;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.util.Log;

/** Teste de integração executado no UID do app; usa apenas a API pública Instrumentation. */
public final class LabTestRunner extends Instrumentation {
    @Override public void onCreate(Bundle args) {
        super.onCreate(args);
        start();
    }
    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            new EnrollmentTest().run(getTargetContext());
            result.putString("stream", "\nPASSOU: Keystore persistente, recusa sem sessão e sem certificado mTLS.\n");
            finish(Activity.RESULT_OK, result);
        } catch (Throwable failure) {
            result.putString("stream", "\nFALHOU: " + Log.getStackTraceString(failure));
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
