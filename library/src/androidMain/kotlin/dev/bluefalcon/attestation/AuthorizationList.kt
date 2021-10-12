package dev.bluefalcon.attestation

import android.annotation.TargetApi
import android.os.Build
import dev.bluefalcon.attestation.Constants.KM_TAG_ACTIVE_DATE_TIME
import dev.bluefalcon.attestation.Constants.KM_TAG_ALGORITHM
import dev.bluefalcon.attestation.Constants.KM_TAG_ALLOW_WHILE_ON_BODY
import dev.bluefalcon.attestation.Constants.KM_TAG_ALL_APPLICATIONS
import dev.bluefalcon.attestation.Constants.KM_TAG_APPLICATION_ID
import dev.bluefalcon.attestation.Constants.KM_TAG_ATTESTATION_APPLICATION_ID
import dev.bluefalcon.attestation.Constants.KM_TAG_ATTESTATION_ID_BRAND
import dev.bluefalcon.attestation.Constants.KM_TAG_ATTESTATION_ID_DEVICE
import dev.bluefalcon.attestation.Constants.KM_TAG_ATTESTATION_ID_IMEI
import dev.bluefalcon.attestation.Constants.KM_TAG_ATTESTATION_ID_MANUFACTURER
import dev.bluefalcon.attestation.Constants.KM_TAG_ATTESTATION_ID_MEID
import dev.bluefalcon.attestation.Constants.KM_TAG_ATTESTATION_ID_MODEL
import dev.bluefalcon.attestation.Constants.KM_TAG_ATTESTATION_ID_PRODUCT
import dev.bluefalcon.attestation.Constants.KM_TAG_ATTESTATION_ID_SERIAL
import dev.bluefalcon.attestation.Constants.KM_TAG_AUTH_TIMEOUT
import dev.bluefalcon.attestation.Constants.KM_TAG_BOOT_PATCH_LEVEL
import dev.bluefalcon.attestation.Constants.KM_TAG_CREATION_DATE_TIME
import dev.bluefalcon.attestation.Constants.KM_TAG_DEVICE_UNIQUE_ATTESTATION
import dev.bluefalcon.attestation.Constants.KM_TAG_DIGEST
import dev.bluefalcon.attestation.Constants.KM_TAG_EC_CURVE
import dev.bluefalcon.attestation.Constants.KM_TAG_KEY_SIZE
import dev.bluefalcon.attestation.Constants.KM_TAG_NO_AUTH_REQUIRED
import dev.bluefalcon.attestation.Constants.KM_TAG_ORIGIN
import dev.bluefalcon.attestation.Constants.KM_TAG_ORIGINATION_EXPIRE_DATE_TIME
import dev.bluefalcon.attestation.Constants.KM_TAG_OS_PATCH_LEVEL
import dev.bluefalcon.attestation.Constants.KM_TAG_OS_VERSION
import dev.bluefalcon.attestation.Constants.KM_TAG_PADDING
import dev.bluefalcon.attestation.Constants.KM_TAG_PURPOSE
import dev.bluefalcon.attestation.Constants.KM_TAG_ROLLBACK_RESISTANCE
import dev.bluefalcon.attestation.Constants.KM_TAG_RSA_PUBLIC_EXPONENT
import dev.bluefalcon.attestation.Constants.KM_TAG_TRUSTED_CONFIRMATION_REQUIRED
import dev.bluefalcon.attestation.Constants.KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED
import dev.bluefalcon.attestation.Constants.KM_TAG_UNLOCKED_DEVICE_REQUIRED
import dev.bluefalcon.attestation.Constants.KM_TAG_USAGE_EXPIRE_DATE_TIME
import dev.bluefalcon.attestation.Constants.KM_TAG_USER_AUTH_TYPE
import dev.bluefalcon.attestation.Constants.KM_TAG_VENDOR_PATCH_LEVEL
import dev.bluefalcon.attestation.Constants.UINT32_MAX
import org.bouncycastle.asn1.*
import java.time.Duration
import java.time.Instant
import java.util.*
import java.util.function.Function
import kotlin.collections.HashMap
import kotlin.collections.HashSet

class AuthorizationList {
    /** Specifies the types of user authenticators that may be used to authorize this key.  */
    enum class UserAuthType {
        USER_AUTH_TYPE_NONE, PASSWORD, FINGERPRINT, USER_AUTH_TYPE_ANY
    }

    var purpose: Optional<Set<Int>>? = null
    var algorithm: Optional<Int>? = null
    var keySize: Optional<Int>? = null
    var digest: Optional<Set<Int>>? = null
    var padding: Optional<Set<Int>>? = null
    var ecCurve: Optional<Int>? = null
    var rsaPublicExponent: Optional<Long>? = null
    var rollbackResistance = false
    var activeDateTime: Optional<Instant>? = null
    var originationExpireDateTime: Optional<Instant>? = null
    var usageExpireDateTime: Optional<Instant>? = null
    var noAuthRequired = false
    var userAuthType: Optional<Set<UserAuthType>>? = null
    var authTimeout: Optional<Duration>? = null
    var allowWhileOnBody = false
    var trustedUserPresenceRequired = false
    var trustedConfirmationRequired = false
    var unlockedDeviceRequired = false
    var allApplications = false
    var applicationId: Optional<ByteArray>? = null
    var creationDateTime: Optional<Instant>? = null
    var origin: Optional<Int>? = null
    var rollbackResistant = false
    var rootOfTrust: Optional<RootOfTrust>? = null
    var osVersion: Optional<Int>? = null
    var osPatchLevel: Optional<Int>? = null
    var attestationApplicationId: Optional<AttestationApplicationId>? = null
    var attestationApplicationIdBytes: Optional<ByteArray>? = null
    var attestationIdBrand: Optional<ByteArray>? = null
    var attestationIdDevice: Optional<ByteArray>? = null
    var attestationIdProduct: Optional<ByteArray>? = null
    var attestationIdSerial: Optional<ByteArray>? = null
    var attestationIdImei: Optional<ByteArray>? = null
    var attestationIdMeid: Optional<ByteArray>? = null
    var attestationIdManufacturer: Optional<ByteArray>? = null
    var attestationIdModel: Optional<ByteArray>? = null
    var vendorPatchLevel: Optional<Int>? = null
    var bootPatchLevel: Optional<Int>? = null
    var individualAttestation = false

    private fun AuthorizationList(
        authorizationList: Array<ASN1Encodable>,
        attestationVersion: Int
    ) {
        val authorizationMap = getAuthorizationMap(authorizationList)
        purpose = findOptionalIntegerSetAuthorizationListEntry(authorizationMap, KM_TAG_PURPOSE)
        algorithm = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_ALGORITHM)
        keySize = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_KEY_SIZE)
        digest = findOptionalIntegerSetAuthorizationListEntry(authorizationMap, KM_TAG_DIGEST)
        padding = findOptionalIntegerSetAuthorizationListEntry(authorizationMap, KM_TAG_PADDING)
        ecCurve = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_EC_CURVE)
        rsaPublicExponent =
            findOptionalLongAuthorizationListEntry(authorizationMap, KM_TAG_RSA_PUBLIC_EXPONENT)
        rollbackResistance =
            findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ROLLBACK_RESISTANCE)
        activeDateTime = findOptionalInstantMillisAuthorizationListEntry(
            authorizationMap,
            KM_TAG_ACTIVE_DATE_TIME
        )
        originationExpireDateTime = findOptionalInstantMillisAuthorizationListEntry(
            authorizationMap, KM_TAG_ORIGINATION_EXPIRE_DATE_TIME
        )
        usageExpireDateTime = findOptionalInstantMillisAuthorizationListEntry(
            authorizationMap, KM_TAG_USAGE_EXPIRE_DATE_TIME
        )
        noAuthRequired =
            findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_NO_AUTH_REQUIRED)
        userAuthType = findOptionalUserAuthType(authorizationMap, KM_TAG_USER_AUTH_TYPE)
        authTimeout =
            findOptionalDurationSecondsAuthorizationListEntry(authorizationMap, KM_TAG_AUTH_TIMEOUT)
        allowWhileOnBody =
            findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ALLOW_WHILE_ON_BODY)
        trustedUserPresenceRequired = findBooleanAuthorizationListEntry(
            authorizationMap,
            KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED
        )
        trustedConfirmationRequired = findBooleanAuthorizationListEntry(
            authorizationMap,
            KM_TAG_TRUSTED_CONFIRMATION_REQUIRED
        )
        unlockedDeviceRequired =
            findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_UNLOCKED_DEVICE_REQUIRED)
        allApplications =
            findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ALL_APPLICATIONS)
        applicationId =
            findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_APPLICATION_ID)
        creationDateTime = findOptionalInstantMillisAuthorizationListEntry(
            authorizationMap, KM_TAG_CREATION_DATE_TIME
        )
        origin = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_ORIGIN)
//        val RootOfTrust = RootOfTrust()
//        rollbackResistant =
//            findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ROLLBACK_RESISTANT)
//        rootOfTrust = Optional.ofNullable(
//            RootOfTrust.createRootOfTrust(
//                findAuthorizationListEntry(authorizationMap, KM_TAG_ROOT_OF_TRUST) as ASN1Sequence?,
//                attestationVersion
//            ) as RootOfTrust
//        )
        osVersion = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_OS_VERSION)
        osPatchLevel =
            findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_OS_PATCH_LEVEL)
//        val AttestationApplicationId = AttestationApplicationId()
//        attestationApplicationId = Optional.ofNullable(
//            AttestationApplicationId.createAttestationApplicationId(
//                findAuthorizationListEntry(
//                    authorizationMap, KM_TAG_ATTESTATION_APPLICATION_ID
//                ) as DEROctetString?
//            ) as AttestationApplicationId
//        )
        attestationApplicationIdBytes = findOptionalByteArrayAuthorizationListEntry(
            authorizationMap, KM_TAG_ATTESTATION_APPLICATION_ID
        )
        attestationIdBrand = findOptionalByteArrayAuthorizationListEntry(
            authorizationMap,
            KM_TAG_ATTESTATION_ID_BRAND
        )
        attestationIdDevice = findOptionalByteArrayAuthorizationListEntry(
            authorizationMap,
            KM_TAG_ATTESTATION_ID_DEVICE
        )
        attestationIdProduct = findOptionalByteArrayAuthorizationListEntry(
            authorizationMap, KM_TAG_ATTESTATION_ID_PRODUCT
        )
        attestationIdSerial = findOptionalByteArrayAuthorizationListEntry(
            authorizationMap,
            KM_TAG_ATTESTATION_ID_SERIAL
        )
        attestationIdImei = findOptionalByteArrayAuthorizationListEntry(
            authorizationMap,
            KM_TAG_ATTESTATION_ID_IMEI
        )
        attestationIdMeid = findOptionalByteArrayAuthorizationListEntry(
            authorizationMap,
            KM_TAG_ATTESTATION_ID_MEID
        )
        attestationIdManufacturer = findOptionalByteArrayAuthorizationListEntry(
            authorizationMap, KM_TAG_ATTESTATION_ID_MANUFACTURER
        )
        attestationIdModel = findOptionalByteArrayAuthorizationListEntry(
            authorizationMap,
            KM_TAG_ATTESTATION_ID_MODEL
        )
        vendorPatchLevel =
            findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_VENDOR_PATCH_LEVEL)
        bootPatchLevel =
            findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_BOOT_PATCH_LEVEL)
        individualAttestation =
            findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_DEVICE_UNIQUE_ATTESTATION)
    }

    fun createAuthorizationList(
        authorizationList: Array<ASN1Encodable>, attestationVersion: Int
    ) {
        return AuthorizationList(authorizationList, attestationVersion)
    }

    private fun getAuthorizationMap(
        authorizationList: Array<ASN1Encodable>
    ): Map<Int, ASN1Primitive?> {
        val authorizationMap: MutableMap<Int, ASN1Primitive?> = HashMap()
        for (entry in authorizationList) {
            val taggedEntry = entry as ASN1TaggedObject
            authorizationMap[taggedEntry.tagNo] = taggedEntry.getObject()
        }
        return authorizationMap
    }

    private fun findAuthorizationListEntry(
        authorizationMap: Map<Int, ASN1Primitive?>, tag: Int
    ): ASN1Primitive? {
        return authorizationMap.getOrDefault(tag, null)
    }

    private fun findOptionalIntegerSetAuthorizationListEntry(
        authorizationMap: Map<Int, ASN1Primitive?>, tag: Int
    ): Optional<Set<Int>>? {
        val ASN1Parsing = ASN1Parsing()
        val asn1Set = findAuthorizationListEntry(authorizationMap, tag) as ASN1Set?
            ?: return Optional.empty()
        val entrySet: MutableSet<Int> = HashSet()
        for (value in asn1Set) {
            entrySet.add(ASN1Parsing.getIntegerFromAsn1(value))
        }
        return Optional.of(entrySet)
    }

    @TargetApi(Build.VERSION_CODES.O)
    private fun findOptionalDurationSecondsAuthorizationListEntry(
        authorizationMap: Map<Int, ASN1Primitive?>, tag: Int
    ): Optional<Duration>? {
        val seconds = findOptionalIntegerAuthorizationListEntry(authorizationMap, tag)
        return seconds.map { seconds: Int ->
            Duration.ofSeconds(
                seconds.toLong()
            )
        }
    }

    private fun findOptionalIntegerAuthorizationListEntry(
        authorizationMap: Map<Int, ASN1Primitive?>, tag: Int
    ): Optional<Int> {
        val ASN1Parsing = ASN1Parsing()
        val entry = findAuthorizationListEntry(authorizationMap, tag)
        return Optional.ofNullable(entry).map(ASN1Parsing::getIntegerFromAsn1)
    }

    @TargetApi(Build.VERSION_CODES.O)
    private fun findOptionalInstantMillisAuthorizationListEntry(
        authorizationMap: Map<Int, ASN1Primitive?>, tag: Int
    ): Optional<Instant>? {
        val millis = findOptionalLongAuthorizationListEntry(authorizationMap, tag)
        return millis.map { epochMilli: Long? ->
            Instant.ofEpochMilli(
                epochMilli!!
            )
        }
    }

    private fun findOptionalLongAuthorizationListEntry(
        authorizationMap: Map<Int, ASN1Primitive?>, tag: Int
    ): Optional<Long> {
        val longEntry = findAuthorizationListEntry(authorizationMap, tag) as ASN1Integer?
        return Optional.ofNullable(longEntry).map { value: ASN1Integer ->
            value.value.toLong()
        }
    }

    private fun findBooleanAuthorizationListEntry(
        authorizationMap: Map<Int, ASN1Primitive?>, tag: Int
    ): Boolean {
        return null != findAuthorizationListEntry(authorizationMap, tag)
    }

    private fun findOptionalByteArrayAuthorizationListEntry(
        authorizationMap: Map<Int, ASN1Primitive?>, tag: Int
    ): Optional<ByteArray>? {
        val entry = findAuthorizationListEntry(authorizationMap, tag) as ASN1OctetString?
        return Optional.ofNullable(entry).map { obj: ASN1OctetString -> obj.octets }
    }

    private fun findOptionalUserAuthType(
        authorizationMap: Map<Int, ASN1Primitive?>, tag: Int
    ): Optional<Set<UserAuthType>>? {
        val AuthorizationList = AuthorizationList()
        val userAuthType = findOptionalLongAuthorizationListEntry(authorizationMap, tag)
        return userAuthType.map(Function<Long, Set<UserAuthType>> { userAuthType: Long? ->
            AuthorizationList.userAuthTypeToEnum(
                userAuthType as Long
            )
        })

    }

    // Visible for testing.
    fun userAuthTypeToEnum(userAuthType: Long): Set<UserAuthType>? {
//    if (userAuthType == 0) {
//      return Set.of(USER_AUTH_TYPE_NONE);
//    }
        val result: MutableSet<UserAuthType> = HashSet()
        if (userAuthType and 1L == 1L) {
            result.add(UserAuthType.PASSWORD)
        }
        if (userAuthType and 2L == 2L) {
            result.add(UserAuthType.FINGERPRINT)
        }
        if (userAuthType == UINT32_MAX) {
            result.add(UserAuthType.USER_AUTH_TYPE_ANY)
        }
        require(!result.isEmpty()) { "Invalid User Auth Type." }
        return result
    }
}