package dev.bluefalcon.rootcheck

import android.content.Context
import com.scottyab.rootbeer.*
import dev.bluefalcon.ApplicationContext

class RootChecker {
    fun checkDeviceRootBeer(context: Context): String {
        val rootBeer = RootBeer(context)
        val testKeys = rootBeer.detectTestKeys()
        val nativeLibrary = rootBeer.canLoadNativeLibrary()
        val boxBinary = rootBeer.checkForBusyBoxBinary()
        val magiskBinary = rootBeer.checkForMagiskBinary()
        val suExists = rootBeer.checkSuExists()
        val nativeLibraryReadAccess = rootBeer.checkForNativeLibraryReadAccess()
        if (rootBeer.isRooted) {
            val string = "RootBeer => Device Rooted\n" +
                    "Test keys : " + (if (testKeys) "true" else "false") +
                    "\nNative Library : " + (if (nativeLibrary) "true" else "false") +
                    "\nBox Binary : " + (if (boxBinary) "true" else "false") +
                    "\nMagisk Binary: " + (if (magiskBinary) "true" else "false") +
                    "\nSuperuser exist : " + (if (suExists) "true" else "false") +
                    "\nNative Library : " + (if (nativeLibrary) "true" else "false") +
                    "\nNative Library Read access : " + if (nativeLibraryReadAccess) "true" else "false"
            println(string)
            return string

            //we found indication of root
        } else {
            val string = "RootBeer : Device Unrooted\n" +
                    "Test keys : " + (if (testKeys) "true" else "false") +
                    "\nNative Library : " + (if (nativeLibrary) "true" else "false") +
                    "\nBox Binary : " + (if (boxBinary) "true" else "false") +
                    "\nMagisk Binary: " + (if (magiskBinary) "true" else "false") +
                    "\nSuperuser exist : " + (if (suExists) "true" else "false") +
                    "\nNative Library : " + (if (nativeLibrary) "true" else "false") +
                    "\nNative Library Read access : " + (if (nativeLibraryReadAccess) "true" else "false")
            println(string)
            return string
            //we didn't find indication of root
        }
    }
}