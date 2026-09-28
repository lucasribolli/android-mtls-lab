package lab.verifier

import com.android.keyattestation.verifier.*
import com.android.keyattestation.verifier.challengecheckers.ChallengeMatcher
import com.google.gson.Gson
import com.google.protobuf.ByteString
import java.math.BigInteger
import java.security.cert.TrustAnchor
import java.time.Instant
import java.util.Base64

/** IPC local via stdin: política, raízes e revogações vêm do Python, nunca do HTTP. */
data class Input(val chain: List<String>, val challenge: String, val roots: List<String>,
                 val revoked: Set<String>, val packageName: String, val minVersion: Long,
                 val signingDigests: List<String>)

fun verify(input: Input): Map<String, Any> {
    require(input.chain.size in 3..8 && input.roots.isNotEmpty())
    require(input.packageName.isNotBlank() && input.minVersion > 0 && input.signingDigests.isNotEmpty())
    val expected = AttestationApplicationId(
        setOf(AttestationPackageInfo(input.packageName, BigInteger.valueOf(input.minVersion))),
        input.signingDigests.map {
            require(it.matches(Regex("[0-9a-f]{64}")))
            ByteString.copyFrom(java.util.HexFormat.of().parseHex(it))
        }.toSet())
    val verifier = Verifier(
        trustAnchorsSource = { input.roots.map { TrustAnchor(it.asX509Certificate(), null) }.toSet() },
        revokedSerialsSource = { input.revoked },
        instantSource = { Instant.now() },
        expectedAttestationApplicationId = expected,
        constraintConfig = ConstraintConfig(
            attestationApplicationId = AttestationApplicationIdConstraint.STRICT,
            securityLevel = CompositeConstraint("Hardware", SecurityLevelConstraint.NOT_SOFTWARE,
                SecurityLevelConstraint.MATCHES_CERTIFICATE)))
    val result = verifier.verify(input.chain.map { it.asX509Certificate() },
        ChallengeMatcher(ByteString.copyFrom(Base64.getDecoder().decode(input.challenge))))
    return when (result) {
        is VerificationResult.Success -> {
            if (!result.deviceLocked || result.verifiedBootState != VerifiedBootState.VERIFIED)
                mapOf("ok" to false, "reason" to "BOOT_NOT_LOCKED_AND_VERIFIED")
            else mapOf("ok" to true, "public_key" to Base64.getEncoder().encodeToString(result.publicKey.encoded),
                "security_level" to result.securityLevel.name, "boot_state" to result.verifiedBootState.name,
                "device_locked" to result.deviceLocked)
        }
        is VerificationResult.PathValidationFailure -> mapOf("ok" to false,
            "reason" to "PATH_${result.cause.reason}")
        is VerificationResult.ConstraintViolation -> mapOf("ok" to false,
            "reason" to "CONSTRAINT_${result.constraintLabel}")
        else -> mapOf("ok" to false, "reason" to result.javaClass.simpleName)
    }
}

fun main() {
    val gson = Gson()
    try {
        val text = System.`in`.readNBytes(1_048_577).toString(Charsets.UTF_8)
        require(text.length <= 1_048_576)
        println(gson.toJson(verify(gson.fromJson(text, Input::class.java))))
    } catch (error: Exception) {
        // Não imprimir certificados, nonce ou material de autenticação nos logs.
        println(gson.toJson(mapOf("ok" to false, "reason" to "INVALID_INPUT_OR_VERIFIER_FAILURE")))
    }
}
