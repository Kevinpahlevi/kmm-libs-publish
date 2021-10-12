package dev.bluefalcon.attestation

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer

class ASN1Parsing {
    fun getBooleanFromAsn1(asn1Value: ASN1Encodable): Boolean {
        return if (asn1Value is ASN1Boolean) {
            asn1Value.isTrue
        } else {
            throw RuntimeException(
                "Boolean value expected; found " + asn1Value.javaClass.name + " instead."
            )
        }
    }

    fun getIntegerFromAsn1(asn1Value: ASN1Encodable): Int {
        return if (asn1Value is ASN1Integer) {
            asn1Value.value.toInt()
        } else if (asn1Value is ASN1Enumerated) {
            asn1Value.value.toInt()
        } else {
            throw IllegalArgumentException(
                "Integer value expected; found " + asn1Value.javaClass.name + " instead."
            )
        }
    }
}