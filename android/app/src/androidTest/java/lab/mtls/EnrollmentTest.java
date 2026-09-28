package lab.mtls;

import java.util.Arrays;
import org.json.JSONObject;

public final class EnrollmentTest {
    private static void fail(String message) { throw new AssertionError(message); }
    private static void assertTrue(boolean value) { if (!value) fail("Condição esperada não satisfeita"); }
    private static void assertFalse(String message, boolean value) { if (value) fail(message); }
    private static void assertNull(Object value) { assertNull("Esperado null", value); }
    private static void assertNull(String message, Object value) { if (value != null) fail(message); }
    private static void assertNotNull(String message, Object value) { if (value == null) fail(message); }
    private static void assertEquals(Object expected, Object actual) {
        if (!expected.equals(actual)) fail("Valores diferentes: " + expected + " / " + actual);
    }
    public void run(String token) throws Exception {
        assertNotNull("Passe -e enrollmentToken TOKEN (token novo do servidor)", token);
        BankIdentity identity = new BankIdentity();
        assertFalse("Teste requer instalação ainda não cadastrada", identity.enrolled());
        identity.ensureKey();
        assertNull("Chave privada não deve ser exportável", identity.privateKey().getEncoded());
        byte[] publicKey = identity.chain()[0].getPublicKey().getEncoded();
        assertTrue(Arrays.equals(publicKey, new BankIdentity().chain()[0].getPublicKey().getEncoded()));
        try {
            BankApi.enroll(identity, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
            fail("Token inválido aceito");
        } catch (java.io.IOException expected) { assertTrue(expected.getMessage().contains("401")); }
        JSONObject enrollment = BankApi.enroll(identity, token);
        assertTrue(identity.enrolled());
        assertNull(identity.privateKey().getEncoded());
        assertTrue(Arrays.equals(publicKey, identity.chain()[0].getPublicKey().getEncoded()));
        BankIdentity reloaded = new BankIdentity();
        assertTrue(reloaded.enrolled());
        JSONObject result = BankApi.account(reloaded);
        assertTrue(result.getBoolean("mtls"));
        assertEquals(enrollment.getString("device_id"), result.getString("device_id"));
        try {
            BankApi.account(null);
            fail("API aceitou conexão sem certificado");
        } catch (javax.net.ssl.SSLException expected) { /* Recusa TLS, não erro genérico de rede. */ }
    }
}
