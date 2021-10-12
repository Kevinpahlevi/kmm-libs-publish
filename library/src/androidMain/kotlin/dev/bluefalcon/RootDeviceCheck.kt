package dev.bluefalcon

import android.content.Context
import dev.bluefalcon.rootcheck.RootChecker
actual class RootDeviceCheck(
    private val context: Context
) {
    actual fun deepCheck(): String {
        val check = RootChecker()
        return check.checkDeviceRootBeer(context)
    }
}