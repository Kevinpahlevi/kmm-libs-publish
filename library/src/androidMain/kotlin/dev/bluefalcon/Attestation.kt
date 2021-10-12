package dev.bluefalcon

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.LocalDate
import java.time.ZoneId
import java.util.*
import javax.security.auth.x500.X500Principal
import dev.bluefalcon.attestation.KeyAttestation;
actual class Attestation() {
    //GENERATE KEYSTORE
    @TargetApi(Build.VERSION_CODES.O)
    actual fun generate() : String {
        val textByte: ByteArray = hexStringToByteArray("key attestation test")
        val Timenow = Date()

        val originationEnd = LocalDate.now().plusDays(11)
        val consumptionEnd = LocalDate.now().plusDays(21)

        val currentLocalDate = LocalDate.now()

        val systemTimeZone = ZoneId.systemDefault()

        val zonedDateTime = originationEnd.atStartOfDay(systemTimeZone)
        val zonedDateTime2 = consumptionEnd.atStartOfDay(systemTimeZone)

        val origin = Date.from(zonedDateTime.toInstant())
        val consumption = Date.from(zonedDateTime2.toInstant())
        val spec = KeyGenParameterSpec.Builder(
            "key0",
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setCertificateSubject(X500Principal("CN=X, O=X"))
            .setCertificateSerialNumber(BigInteger.ONE)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setAttestationChallenge(textByte)
            .setKeyValidityStart(Timenow)
            .setKeyValidityForOriginationEnd(origin)
            .setKeyValidityForConsumptionEnd(consumption)
            .build()
        val generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
        generator.initialize(spec)

        generator.generateKeyPair()
        val keystore = KeyStore.getInstance("AndroidKeyStore")
        keystore.load(null)
        val privateKeyEntry = keystore
            .getEntry("key0", null) as KeyStore.PrivateKeyEntry


        val keyFactory = KeyFactory.getInstance(
            privateKeyEntry.privateKey.algorithm,
            "AndroidKeyStore"
        )
        val keyInfo = keyFactory.getKeySpec(
            privateKeyEntry.privateKey,
            KeyInfo::class.java
        )
        //get public
        //get public

        val certificates = keystore.getCertificateChain("key0")


        Log.i("Attestation", "Is key in secure hardware: " + keyInfo.isInsideSecureHardware)
        Log.i("Attestation", "Number of certificates in the chain: " + privateKeyEntry.certificateChain.size)
        Log.i("Attestation", "first: " + privateKeyEntry.certificateChain[0].type)
        Log.i("Attestation", "second: " + privateKeyEntry.certificateChain[1].type)
        Log.i("Attestation", "third: " + privateKeyEntry.certificateChain[2].type)
        Log.i("Attestation", "publickey: " + privateKeyEntry.certificateChain[1].publicKey)
        if (certificates != null) {
            Log.i("Attestation", "publickey cert: " + certificates.size)
        }

        val certs: Array<X509Certificate?>?
        certs = arrayOfNulls(certificates.size)
        for (i in certs.indices) certs[i] = certificates[i] as X509Certificate



        val verify = KeyAttestation();
        val hasil: String = verify.verifyCertificateChain(certs)

        return "Is key in secure hardware: " + keyInfo.isInsideSecureHardware+ "\t" + hasil
    }

    fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4)
                    + Character.digit(s[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }


}

