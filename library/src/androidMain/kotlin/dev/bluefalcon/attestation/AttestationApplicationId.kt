package dev.bluefalcon.attestation

import dev.bluefalcon.attestation.Constants.ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX
import dev.bluefalcon.attestation.Constants.ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX
import dev.bluefalcon.attestation.Constants.ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX
import dev.bluefalcon.attestation.Constants.ATTESTATION_PACKAGE_INFO_VERSION_INDEX
import org.bouncycastle.asn1.*
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.*
import kotlin.Comparator
import kotlin.collections.ArrayList

class AttestationApplicationId {
    var packageInfos: MutableList<AttestationPackageInfo>? = null
    var signatureDigests: MutableList<ByteArray>? = null

    @Throws(IOException::class)
    private fun AttestationApplicationId(attestationApplicationId: DEROctetString) {
        val attestationApplicationIdSequence =
            ASN1Sequence.fromByteArray(attestationApplicationId.octets) as ASN1Sequence
        val attestationPackageInfos = attestationApplicationIdSequence.getObjectAt(
            ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX
        ) as ASN1Set
        packageInfos = ArrayList()
        for (packageInfo in attestationPackageInfos) {
            (packageInfos as ArrayList<AttestationPackageInfo>).add(AttestationPackageInfo(packageInfo as ASN1Sequence))
        }
        val digests = attestationApplicationIdSequence.getObjectAt(
            ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX
        ) as ASN1Set
        signatureDigests = ArrayList()
        for (digest in digests) {
            (signatureDigests as ArrayList<ByteArray>).add((digest as ASN1OctetString).octets)
        }
    }

    fun AttestationApplicationId(
        packageInfos: MutableList<AttestationPackageInfo>?,
        signatureDigests: MutableList<ByteArray>?
    ) {
        this.packageInfos = packageInfos
        this.signatureDigests = signatureDigests
    }

    fun createAttestationApplicationId(
        attestationApplicationId: DEROctetString?
    ): Unit? {
        return if (attestationApplicationId == null) {
            null
        } else try {
            AttestationApplicationId(attestationApplicationId)
        } catch (e: IOException) {
            null
        }
    }

//    operator fun compareTo(other: AttestationApplicationId): Int? {
//        var res = other.packageInfos?.let { Integer.compare(packageInfos!!.size, it.size) }
//        if (res != 0) {
//            return res
//        }
//        for (i in packageInfos!!.indices) {
//            res = packageInfos!![i].compareTo(other.packageInfos?.get(i))
//            if (res != 0) {
//                return res
//            }
//        }
//        res = other.signatureDigests?.let { Integer.compare(signatureDigests!!.size, it.size) }!!
//        if (res != 0) {
//            return res
//        }
//        val cmp = ByteArrayComparator()
//        for (i in signatureDigests!!.indices) {
//            res = other.signatureDigests?.get(i)?.let { cmp.compare(signatureDigests!![i], it) }!!
//            if (res != 0) {
//                return res
//            }
//        }
//        return res
//    }

//    override fun equals(o: Any?): Boolean {
//        return (o is AttestationApplicationId
//                && compareTo(o) == 0)
//    }

    override fun hashCode(): Int {
        return Objects.hash(packageInfos, Arrays.deepHashCode(signatureDigests!!.toTypedArray()))
    }

    /** Provides package's name and version number.  */
    class AttestationPackageInfo : Comparable<AttestationPackageInfo?> {
        val packageName: String
        val version: Long

        constructor(packageInfo: ASN1Sequence) {
            packageName = String(
                (packageInfo.getObjectAt(ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX) as ASN1OctetString)
                    .octets,
                StandardCharsets.UTF_8
            )
            version =
                (packageInfo.getObjectAt(ATTESTATION_PACKAGE_INFO_VERSION_INDEX) as ASN1Integer)
                    .value
                    .toLong()
        }

        internal constructor(packageName: String, version: Long) {
            this.packageName = packageName
            this.version = version
        }

        @JvmName("compareTo1")
        operator fun compareTo(other: AttestationApplicationId.AttestationPackageInfo): Int {
            var res = packageName.compareTo(other.packageName)
            if (res != 0) {
                return res
            }
            res = java.lang.Long.compare(version, other.version)
            return if (res != 0) {
                res
            } else res
        }

        override fun equals(o: Any?): Boolean {
            return o is AttestationPackageInfo && compareTo(o) == 0
        }

        override fun hashCode(): Int {
            return Objects.hash(packageName, version)
        }

        override fun compareTo(other: AttestationPackageInfo?): Int {
            TODO("Not yet implemented")
        }
    }

    private class ByteArrayComparator : Comparator<ByteArray> {
        override fun compare(a: ByteArray, b: ByteArray): Int {
            var res = Integer.compare(a.size, b.size)
            if (res != 0) {
                return res
            }
            for (i in a.indices) {
                res = java.lang.Byte.compare(a[i], b[i])
                if (res != 0) {
                    return res
                }
            }
            return res
        }
    }
}