package dev.bluefalcon

import android.Manifest
import android.annotation.TargetApi
import android.bluetooth.*
import android.bluetooth.BluetoothAdapter.STATE_CONNECTED
import android.bluetooth.BluetoothAdapter.STATE_DISCONNECTED
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.os.ParcelUuid
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.time.LocalDate
import java.time.ZoneId
import java.util.*
import javax.security.auth.x500.X500Principal

actual class BlueFalcon actual constructor(
    private val context: ApplicationContext,
    private val serviceUUID: String?
) {
    actual val delegates: MutableSet<BlueFalconDelegate> = mutableSetOf()
    private val bluetoothManager: BluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val mBluetoothScanCallBack = BluetoothScanCallBack()
    private val mGattClientCallback = GattClientCallback()
    var transportMethod: Int = BluetoothDevice.TRANSPORT_AUTO
    actual var isScanning: Boolean = false


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


        Log.i("aa", "Is key in secure hardware: " + keyInfo.isInsideSecureHardware)
        Log.i("aa", "Number of certificates in the chain: " + privateKeyEntry.certificateChain.size)
        Log.i("aa", "first: " + privateKeyEntry.certificateChain[0].type)
        Log.i("aa", "second: " + privateKeyEntry.certificateChain[1].type)
        Log.i("aa", "third: " + privateKeyEntry.certificateChain[2].type)
        Log.i("aa", "publickey: " + privateKeyEntry.certificateChain[1].publicKey)
        Log.i("aa", "publickey cert: " + certificates.size)

//        val cos =
//            FileOutputStream(Environment.getExternalStorageDirectory().absolutePath + "/Download/first11122.der")
//
//        cos.write(certificates[0].encoded)
//
//        cos.flush()
//        cos.close()
//
//        val cos2 =
//            FileOutputStream(Environment.getExternalStorageDirectory().absolutePath + "/Download/second211123.der")
//
//        cos2.write(certificates[1].encoded)
//
//        cos2.flush()
//        cos2.close()
//
//        val cos3 =
//            FileOutputStream(Environment.getExternalStorageDirectory().absolutePath + "/Download/third311123.der")
//        cos3.write(certificates[2].encoded)
//
//        cos3.flush()
//        cos3.close()
//
//        if (certificates.size == 4) {
//            val cos4 =
//                FileOutputStream(Environment.getExternalStorageDirectory().absolutePath + "/Download/fourth41121.der")
//            cos4.write(certificates[3].encoded)
//            cos4.flush()
//            cos4.close()
//        }
        return "Is key in secure hardware: " + keyInfo.isInsideSecureHardware
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




    actual fun connect(bluetoothPeripheral: BluetoothPeripheral, autoConnect: Boolean) {
        log("connect")
        bluetoothPeripheral.bluetoothDevice.connectGatt(context, autoConnect, mGattClientCallback, transportMethod)
    }

    actual fun disconnect(bluetoothPeripheral: BluetoothPeripheral) {
        log("disconnect")
        mGattClientCallback.gattForDevice(bluetoothPeripheral.bluetoothDevice)?.apply {
            disconnect()
            close()
        }
        delegates.forEach { it.didDisconnect(bluetoothPeripheral) }
    }

    actual fun stopScanning() {
        isScanning = false
        bluetoothManager.adapter?.bluetoothLeScanner?.stopScan(mBluetoothScanCallBack)
    }

    actual fun scan() {
        if (context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED)
            throw BluetoothPermissionException()
        log("BT Scan started")
        isScanning = true

        val filterBuilder = ScanFilter.Builder()
        serviceUUID?.let {
            filterBuilder.setServiceUuid(ParcelUuid(UUID.fromString(it)))
        }
        val filter = filterBuilder.build()
        val filters = listOf(filter)
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
            .build()
        val bluetoothScanner = bluetoothManager.adapter?.bluetoothLeScanner
        bluetoothScanner?.startScan(filters, settings, mBluetoothScanCallBack)
    }

    private fun fetchCharacteristic(
        bluetoothCharacteristic: BluetoothCharacteristic,
        gatt: BluetoothGatt): List<BluetoothCharacteristic> =
        gatt.services.flatMap { service ->
            service.characteristics.filter {
                it.uuid == bluetoothCharacteristic.characteristic.uuid
            }.map {
                BluetoothCharacteristic(it)
            }
        }

    actual fun readCharacteristic(
        bluetoothPeripheral: BluetoothPeripheral,
        bluetoothCharacteristic: BluetoothCharacteristic
    ) {
        mGattClientCallback.gattForDevice(bluetoothPeripheral.bluetoothDevice)?.let { gatt ->
            fetchCharacteristic(bluetoothCharacteristic, gatt)
                .forEach { gatt.readCharacteristic(it.characteristic) }
        }
    }

    private fun setCharacteristicNotification(
        bluetoothPeripheral: BluetoothPeripheral,
        bluetoothCharacteristic: BluetoothCharacteristic,
        enable: Boolean,
        descriptorValue: ByteArray
    ) {
        mGattClientCallback.gattForDevice(bluetoothPeripheral.bluetoothDevice)?.let { gatt ->
            fetchCharacteristic(bluetoothCharacteristic, gatt)
                .forEach {
                    gatt.setCharacteristicNotification(it.characteristic, enable)
                    it.characteristic.descriptors.forEach { descriptor ->
                        descriptor.value = descriptorValue
                        gatt.writeDescriptor(descriptor)
                    }
                }
        }
    }

    actual fun notifyCharacteristic(
        bluetoothPeripheral: BluetoothPeripheral,
        bluetoothCharacteristic: BluetoothCharacteristic,
        notify: Boolean
    ) {
        setCharacteristicNotification(
            bluetoothPeripheral,
            bluetoothCharacteristic,
            notify,
            if (notify)
                BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            else
                BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
        )
    }

    actual fun indicateCharacteristic(
        bluetoothPeripheral: BluetoothPeripheral,
        bluetoothCharacteristic: BluetoothCharacteristic,
        indicate: Boolean
    ) {
        setCharacteristicNotification(
            bluetoothPeripheral,
            bluetoothCharacteristic,
            indicate,
            if (indicate)
                BluetoothGattDescriptor.ENABLE_INDICATION_VALUE
            else
                BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
        )
    }

    actual fun notifyAndIndicateCharacteristic(
        bluetoothPeripheral: BluetoothPeripheral,
        bluetoothCharacteristic: BluetoothCharacteristic,
        enable: Boolean
    ) {
        setCharacteristicNotification(
            bluetoothPeripheral,
            bluetoothCharacteristic,
            enable,
            if (enable)
                byteArrayOf(
                    0x03,
                    0x00
                )
            else
                BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
        )
    }

    actual fun writeCharacteristic(
        bluetoothPeripheral: BluetoothPeripheral,
        bluetoothCharacteristic: BluetoothCharacteristic,
        value: String,
        writeType: Int?
    ) {
        mGattClientCallback.gattForDevice(bluetoothPeripheral.bluetoothDevice)?.let { gatt ->
            fetchCharacteristic(bluetoothCharacteristic, gatt)
                .forEach {
                    writeType?.let { writeType ->
                        it.characteristic.writeType = writeType
                    }
                    it.characteristic.setValue(value)
                    gatt.writeCharacteristic(it.characteristic)
                }
        }
    }

    actual fun writeCharacteristicWithoutEncoding(
        bluetoothPeripheral: BluetoothPeripheral,
        bluetoothCharacteristic: BluetoothCharacteristic,
        value: ByteArray,
        writeType: Int?
    ) {
        writeCharacteristic(bluetoothPeripheral, bluetoothCharacteristic, value, writeType)
    }

    actual fun writeCharacteristic(
        bluetoothPeripheral: BluetoothPeripheral,
        bluetoothCharacteristic: BluetoothCharacteristic,
        value: ByteArray,
        writeType: Int?
    ) {
        mGattClientCallback.gattForDevice(bluetoothPeripheral.bluetoothDevice)?.let { gatt ->
            fetchCharacteristic(bluetoothCharacteristic, gatt)
                .forEach {
                    writeType?.let { writeType ->
                        it.characteristic.writeType = writeType
                    }
                    it.characteristic.setValue(value)
                    gatt.writeCharacteristic(it.characteristic)
                }
        }
    }

    actual fun readDescriptor(
        bluetoothPeripheral: BluetoothPeripheral,
        bluetoothCharacteristic: BluetoothCharacteristic,
        bluetoothCharacteristicDescriptor: BluetoothCharacteristicDescriptor
    ) {
        mGattClientCallback.gattForDevice(bluetoothPeripheral.bluetoothDevice)?.readDescriptor(bluetoothCharacteristicDescriptor)
        log("readDescriptor -> ${bluetoothCharacteristicDescriptor.uuid}")
    }

    actual fun changeMTU(bluetoothPeripheral: BluetoothPeripheral, mtuSize: Int) {
        mGattClientCallback.gattForDevice(bluetoothPeripheral.bluetoothDevice)?.requestMtu(mtuSize)
    }

    inner class BluetoothScanCallBack: ScanCallback() {

        override fun onScanResult(callbackType: Int, result: ScanResult?) {
            addScanResult(result)
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>?) {
            results?.forEach { addScanResult(it) }
        }

        override fun onScanFailed(errorCode: Int) {
            log("Failed to scan with code $errorCode")
        }

        private fun addScanResult(result: ScanResult?) {
            result?.let { scanResult ->
                scanResult.device?.let { device ->
                    delegates.forEach {
                        it.didDiscoverDevice(BluetoothPeripheral(device))
                    }
                }
            }
        }

    }

    inner class GattClientCallback: BluetoothGattCallback() {

        private val gatts: MutableList<BluetoothGatt> = mutableListOf()

        private fun addGatt(gatt: BluetoothGatt) {
            if (gatts.firstOrNull { it.device == gatt.device } == null) {
                gatts.add(gatt)
            }
        }

        private fun removeGatt(gatt: BluetoothGatt) {
            gatts.remove(gatt)
        }

        fun gattForDevice(bluetoothDevice: BluetoothDevice): BluetoothGatt? =
            gatts.firstOrNull { it.device == bluetoothDevice }

        override fun onConnectionStateChange(gatt: BluetoothGatt?, status: Int, newState: Int) {
            super.onConnectionStateChange(gatt, status, newState)
            log("onConnectionStateChange")
            gatt?.let { bluetoothGatt ->
                bluetoothGatt.device.let {
                    //BluetoothProfile#STATE_DISCONNECTED} or {@link BluetoothProfile#STATE_CONNECTED}
                    if (newState == STATE_CONNECTED) {
                        addGatt(bluetoothGatt)
                        bluetoothGatt.readRemoteRssi()
                        bluetoothGatt.discoverServices()
                        delegates.forEach {
                            it.didConnect(BluetoothPeripheral(bluetoothGatt.device))
                        }
                    } else if (newState == STATE_DISCONNECTED) {
                        removeGatt(bluetoothGatt)
                        delegates.forEach {
                            it.didDisconnect(BluetoothPeripheral(bluetoothGatt.device))
                        }
                    }
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt?, status: Int) {
            log("onServicesDiscovered")
            if (status != BluetoothGatt.GATT_SUCCESS) {
                return
            }
            gatt?.device?.let { bluetoothDevice ->
                gatt.services.let { services ->
                    log("onServicesDiscovered -> $services")
                    val bluetoothPeripheral = BluetoothPeripheral(bluetoothDevice)
                    bluetoothPeripheral.deviceServices = services.map { BluetoothService(it) }
                    delegates.forEach {
                        it.didDiscoverServices(bluetoothPeripheral)
                        it.didDiscoverCharacteristics(bluetoothPeripheral)
                    }
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt?, mtu: Int, status: Int) {
            super.onMtuChanged(gatt, mtu, status)
            log("onMtuChanged$mtu status:$status")
            if (status != BluetoothGatt.GATT_SUCCESS) {
                return
            }
            gatt?.device?.let { bluetoothDevice ->
                delegates.forEach {
                    it.didUpdateMTU(BluetoothPeripheral(bluetoothDevice))
                }
            }
        }

        override fun onReadRemoteRssi(gatt: BluetoothGatt?, rssi: Int, status: Int) {
            log("onReadRemoteRssi $rssi")
            gatt?.device?.let { bluetoothDevice ->
                val bluetoothPeripheral = BluetoothPeripheral(bluetoothDevice)
                bluetoothPeripheral.rssi = rssi.toFloat()
                delegates.forEach {
                    it.didRssiUpdate(
                        bluetoothPeripheral
                    )
                }
            }
        }

        override fun onCharacteristicRead(gatt: BluetoothGatt?, characteristic: BluetoothGattCharacteristic?, status: Int) {
            handleCharacteristicValueChange(gatt, characteristic)
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt?, characteristic: BluetoothGattCharacteristic?) {
            handleCharacteristicValueChange(gatt, characteristic)
        }

        override fun onDescriptorRead(gatt: BluetoothGatt?, descriptor: BluetoothGattDescriptor?, status: Int) {
            log("onDescriptorRead $descriptor")
            descriptor?.let { forcedDescriptor ->
                gatt?.device?.let { bluetoothDevice ->
                    log("onDescriptorRead value ${forcedDescriptor.value}")
                    delegates.forEach {
                        it.didReadDescriptor(
                            BluetoothPeripheral(bluetoothDevice),
                            forcedDescriptor
                        )
                    }
                }
            }
        }

        private fun handleCharacteristicValueChange(gatt: BluetoothGatt?, characteristic: BluetoothGattCharacteristic?) {
            characteristic?.let { forcedCharacteristic ->
                val characteristic = BluetoothCharacteristic(forcedCharacteristic)
                gatt?.device?.let { bluetoothDevice ->
                    delegates.forEach {
                        it.didCharacteristcValueChanged(BluetoothPeripheral(bluetoothDevice), characteristic)
                    }
                }
            }
        }
    }



}