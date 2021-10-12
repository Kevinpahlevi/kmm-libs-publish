package dev.bluefalcon.attestation

import dev.bluefalcon.attestation.Constants.KM_VERIFIED_BOOT_STATE_FAILED
import dev.bluefalcon.attestation.Constants.KM_VERIFIED_BOOT_STATE_SELF_SIGNED
import dev.bluefalcon.attestation.Constants.KM_VERIFIED_BOOT_STATE_UNVERIFIED
import dev.bluefalcon.attestation.Constants.KM_VERIFIED_BOOT_STATE_VERIFIED
import dev.bluefalcon.attestation.Constants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX
import dev.bluefalcon.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX
import dev.bluefalcon.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX
import dev.bluefalcon.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence

class RootOfTrust {
    var verifiedBootKey: ByteArray? = null
    var deviceLocked = false
    var verifiedBootState: VerifiedBootState? = null
    var verifiedBootHash: ByteArray? = null

    private fun RootOfTrust(rootOfTrust: ASN1Sequence, attestationVersion: Int) {
        val ASN1Parsing = ASN1Parsing()
        verifiedBootKey =
            (rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX) as ASN1OctetString)
                .octets
        deviceLocked =
            ASN1Parsing.getBooleanFromAsn1(rootOfTrust.getObjectAt(ROOT_OF_TRUST_DEVICE_LOCKED_INDEX))
        verifiedBootState = verifiedBootStateToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX)
            )
        )
        if (attestationVersion >= 3) {
            verifiedBootHash =
                (rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX) as ASN1OctetString)
                    .octets
        } else {
            verifiedBootHash = null
        }
    }

    fun createRootOfTrust(rootOfTrust: ASN1Sequence?, attestationVersion: Int): Unit? {
        if (rootOfTrust === null){
            return null
        }
        return RootOfTrust(rootOfTrust, attestationVersion)
    }

    private fun verifiedBootStateToEnum(securityLevel: Int): VerifiedBootState? {
        return when (securityLevel) {
            KM_VERIFIED_BOOT_STATE_VERIFIED -> VerifiedBootState.VERIFIED
            KM_VERIFIED_BOOT_STATE_SELF_SIGNED -> VerifiedBootState.SELF_SIGNED
            KM_VERIFIED_BOOT_STATE_UNVERIFIED -> VerifiedBootState.UNVERIFIED
            KM_VERIFIED_BOOT_STATE_FAILED -> VerifiedBootState.FAILED
            else -> throw IllegalArgumentException("Invalid verified boot state.")
        }
    }

    /**
     * This provides the device's current boot state, which represents the level of protection
     * provided to the user and to apps after the device finishes booting.
     */
    enum class VerifiedBootState {
        VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED
    }
}