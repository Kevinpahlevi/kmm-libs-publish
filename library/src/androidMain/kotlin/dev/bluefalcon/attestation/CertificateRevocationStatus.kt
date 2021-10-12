package dev.bluefalcon.attestation

import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.FileReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.Reader
import java.math.BigInteger
import java.net.MalformedURLException
import java.net.URL

class CertificateRevocationStatus {
    private val STATUS_URL = "https://android.googleapis.com/attestation/status"
    var status: Status? = null
    var reason: Reason? = null
    var comment: String? = null
    var expires: String? = null

    @Throws(IOException::class)
    fun loadStatusFromFile(
        serialNumber: BigInteger,
        filePath: String?
    ): CertificateRevocationStatus? {
        return loadStatusFromFile(serialNumber.toString(16), filePath)
    }

    @Throws(IOException::class)
    fun loadStatusFromFile(serialNumber: String, filePath: String?): CertificateRevocationStatus? {
        val reader = FileReader(filePath)
        return decodeStatus(serialNumber, reader)
    }


    fun fetchStatus(serialNumber: BigInteger): CertificateRevocationStatus? {
        return fetchStatus(serialNumber.toString(16))
    }

    @Throws(IOException::class)
    fun fetchStatus(serialNumber: String): CertificateRevocationStatus? {
        val url: URL
        url = try {
            URL(STATUS_URL)
        } catch (e: MalformedURLException) {
            throw IllegalStateException(e)
        }
        val statusListReader = InputStreamReader(url.openStream())
        return decodeStatus(serialNumber, statusListReader)
    }

    private fun decodeStatus(
        serialNumber: String,
        statusListReader: Reader
    ): CertificateRevocationStatus? {
        var serialNumber: String? = serialNumber
        requireNotNull(serialNumber) { "serialNumber cannot be null" }
        serialNumber = serialNumber.toLowerCase()
        val entries = JsonParser().parse(statusListReader)
            .asJsonObject
            .getAsJsonObject("entries")
        return if (!entries.has(serialNumber)) {
            null
        } else Gson().fromJson(entries[serialNumber], CertificateRevocationStatus::class.java)
    }


    enum class Status {
        REVOKED, SUSPENDED
    }

    enum class Reason {
        UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED, SOFTWARE_FLAW
    }

    fun CertificateRevocationStatus() {
        status = Status.REVOKED
        reason = Reason.UNSPECIFIED
        comment = null
        expires = null
    }
}