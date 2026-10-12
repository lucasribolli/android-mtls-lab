package lab.mtls.embedded;

import android.content.Context;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Arrays;

final class CredentialValidator {
    private final X509Certificate trusted;
    CredentialValidator(Context context) throws Exception {
        try (InputStream in = context.getResources().openRawResource(R.raw.lab_ca)) {
            trusted = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }
    void validate(PrivateKey privateKey, X509Certificate[] chain) throws Exception {
        if (chain.length != 2) throw new CertificateException("Cadeia deve conter cliente e CA esperada.");
        X509Certificate leaf = chain[0], issuer = chain[1];
        issuer.checkValidity(); leaf.checkValidity();
        if (!Arrays.equals(trusted.getEncoded(), issuer.getEncoded()) || issuer.getBasicConstraints() < 0
                || issuer.getKeyUsage() == null || !issuer.getKeyUsage()[5]
                || leaf.getBasicConstraints() != -1
                || !leaf.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                || leaf.getKeyUsage() == null || !leaf.getKeyUsage()[0]
                || leaf.getExtendedKeyUsage() == null
                || !leaf.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2")
                || !fingerprint(leaf).equals(GeneratedCredential.EXPECTED_FINGERPRINT)
                || !privateKey.getAlgorithm().equals(GeneratedCredential.KEY_ALGORITHM)
                || !leaf.getPublicKey().getAlgorithm().equals(GeneratedCredential.KEY_ALGORITHM))
            throw new CertificateException("Identidade, CA, algoritmo ou uso do certificado inesperado.");
        leaf.verify(issuer.getPublicKey());
        issuer.verify(issuer.getPublicKey());
        if (!"RSA".equals(GeneratedCredential.KEY_ALGORITHM)
                || !(leaf.getPublicKey() instanceof RSAKey)
                || ((RSAKey)leaf.getPublicKey()).getModulus().bitLength() != GeneratedCredential.KEY_SIZE)
            throw new CertificateException("Perfil de algoritmo/tamanho não implementado nesta versão.");
        // A correspondência também é testada depois da importação, usando operação do Keystore.
        byte[] challenge = new byte[32]; new SecureRandom().nextBytes(challenge);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey); signer.update(challenge);
        byte[] signature = signer.sign();
        signer.initVerify(leaf.getPublicKey()); signer.update(challenge);
        if (!signer.verify(signature)) throw new CertificateException("Chave privada não corresponde à pública.");
        Arrays.fill(challenge, (byte)0); Arrays.fill(signature, (byte)0);
    }
    static String fingerprint(X509Certificate certificate) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))
            result.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return result.toString();
    }
}
