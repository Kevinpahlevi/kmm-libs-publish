package dev.bluefalcon.attestation

import android.util.Log
import dev.bluefalcon.attestation.Constants.ATTESTATION_CHALLENGE_INDEX
import dev.bluefalcon.attestation.Constants.ATTESTATION_SECURITY_LEVEL_INDEX
import dev.bluefalcon.attestation.Constants.ATTESTATION_VERSION_INDEX
import dev.bluefalcon.attestation.Constants.KEYMASTER_SECURITY_LEVEL_INDEX
import dev.bluefalcon.attestation.Constants.KEYMASTER_VERSION_INDEX
import dev.bluefalcon.attestation.Constants.KEY_DESCRIPTION_OID
import dev.bluefalcon.attestation.Constants.KM_SECURITY_LEVEL_SOFTWARE
import dev.bluefalcon.attestation.Constants.KM_SECURITY_LEVEL_STRONG_BOX
import dev.bluefalcon.attestation.Constants.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import dev.bluefalcon.attestation.Constants.SW_ENFORCED_INDEX
import dev.bluefalcon.attestation.Constants.TEE_ENFORCED_INDEX
import dev.bluefalcon.attestation.Constants.UNIQUE_ID_INDEX
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import java.io.IOException
import java.security.cert.X509Certificate

class ParsedAttestationRecord {
    var attestationVersion: Int = 0
    var attestationSecurityLevel: SecurityLevel? = null
    var keymasterVersion = 0
    var keymasterSecurityLevel: SecurityLevel? = null
    var attestationChallenge: ByteArray? = null
    var uniqueId: ByteArray? = null
    var softwareEnforced: AuthorizationList? = null
    var teeEnforced: AuthorizationList? = null

    private fun ParsedAttestationRecord(extensionData: ASN1Sequence) {
        val ASN1Parsing = ASN1Parsing()
        val AuthorizationList = AuthorizationList()
        this.attestationVersion =
            ASN1Parsing.getIntegerFromAsn1(extensionData.getObjectAt(ATTESTATION_VERSION_INDEX))
        this.attestationSecurityLevel = securityLevelToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                extensionData.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX)
            )
        )
        this.keymasterVersion =
            ASN1Parsing.getIntegerFromAsn1(extensionData.getObjectAt(KEYMASTER_VERSION_INDEX))
        this.keymasterSecurityLevel = securityLevelToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                extensionData.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX)
            )
        )
        this.attestationChallenge =
            (extensionData.getObjectAt(ATTESTATION_CHALLENGE_INDEX) as ASN1OctetString).octets
        this.uniqueId = (extensionData.getObjectAt(UNIQUE_ID_INDEX) as ASN1OctetString).octets
    }

    @Throws(IOException::class)
    fun createParsedAttestationRecord(cert: X509Certificate) {
        val extensionData = extractAttestationSequence(cert)
        val ASN1Parsing = ASN1Parsing()
        val test =  ASN1Parsing.getIntegerFromAsn1(extensionData.getObjectAt(ATTESTATION_VERSION_INDEX))
        Log.i("Attestation", "Version Attestation => "+test.toString())
        val test2 = securityLevelToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                extensionData.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX)
            )
        )
        Log.i("Attestation", "Security Level =>"+test2.toString())
        val AuthorizationListSW = AuthorizationList()
        // INSERT SW
        AuthorizationListSW.createAuthorizationList(
            (extensionData.getObjectAt(SW_ENFORCED_INDEX) as ASN1Sequence).toArray(),
            attestationVersion
        )
        this.softwareEnforced = AuthorizationListSW
        Log.i("Attestation", "software enforce rollback =>"+AuthorizationListSW.rollbackResistance)
        val AuthorizationListTEE = AuthorizationList()
        // INSERT TEE
        AuthorizationListTEE.createAuthorizationList(
            (extensionData.getObjectAt(TEE_ENFORCED_INDEX) as ASN1Sequence).toArray(),
            attestationVersion
        )
        this.teeEnforced = AuthorizationListTEE
        Log.i("Attestation", "software enforce rollback =>"+AuthorizationListTEE.purpose)
        return ParsedAttestationRecord(extensionData)

    }

    private fun securityLevelToEnum(securityLevel: Int): SecurityLevel? {
        return when (securityLevel) {
            KM_SECURITY_LEVEL_SOFTWARE -> SecurityLevel.SOFTWARE
            KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TRUSTED_ENVIRONMENT
            KM_SECURITY_LEVEL_STRONG_BOX -> SecurityLevel.STRONG_BOX
            else -> throw IllegalArgumentException("Invalid security level.")
        }
    }

    @Throws(IOException::class)
    private fun extractAttestationSequence(attestationCert: X509Certificate): ASN1Sequence {
        val attestationExtensionBytes = attestationCert.getExtensionValue(KEY_DESCRIPTION_OID)
        require(!(attestationExtensionBytes == null || attestationExtensionBytes.size == 0)) { "Couldn't find the keystore attestation extension data." }
        var decodedSequence: ASN1Sequence
        ASN1InputStream(attestationExtensionBytes).use { asn1InputStream ->
            // The extension contains one object, a sequence, in the
            // Distinguished Encoding Rules (DER)-encoded form. Get the DER
            // bytes.
            val derSequenceBytes =
                (asn1InputStream.readObject() as ASN1OctetString).octets
            ASN1InputStream(derSequenceBytes).use { seqInputStream ->
                decodedSequence = seqInputStream.readObject() as ASN1Sequence
            }
        }
        return decodedSequence
    }

    /**
     * This indicates the extent to which a software feature, such as a key pair, is protected based
     * on its location within the device.
     */
    enum class SecurityLevel {
        SOFTWARE, TRUSTED_ENVIRONMENT, STRONG_BOX
    }
}