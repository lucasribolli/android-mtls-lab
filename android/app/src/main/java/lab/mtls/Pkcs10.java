package lab.mtls;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import javax.security.auth.x500.X500Principal;

/** Codificação DER do perfil fixo PKCS#10 RSA/SHA-256 (RFC 2986).
 * A criptografia é feita pelo Signature/AndroidKeyStore, sem exportar a chave.
 */
final class Pkcs10 {
    private Pkcs10() {}

    static String create(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        byte[] info = der(0x30, concat(
                new byte[]{0x02, 0x01, 0x00}, // version = 0
                new X500Principal("CN=pending-enrollment").getEncoded(),
                publicKey.getEncoded(), // SubjectPublicKeyInfo
                new byte[]{(byte) 0xa0, 0x00})); // attributes [0], vazio
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(info);
        // AlgorithmIdentifier: OID 1.2.840.113549.1.1.11, parâmetros NULL.
        byte[] algorithm = {0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48,
                (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00};
        byte[] csr = der(0x30, concat(info, algorithm,
                der(0x03, concat(new byte[]{0}, signer.sign()))));
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(csr)
                + "\n-----END CERTIFICATE REQUEST-----\n";
    }

    private static byte[] concat(byte[]... parts) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.write(part);
        return out.toByteArray();
    }

    private static byte[] der(int tag, byte[] value) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (value.length < 128) out.write(value.length);
        else if (value.length <= 255) { out.write(0x81); out.write(value.length); }
        else if (value.length <= 65535) {
            out.write(0x82); out.write(value.length >> 8); out.write(value.length);
        } else throw new IllegalArgumentException("Objeto DER grande demais");
        out.write(value);
        return out.toByteArray();
    }
}
