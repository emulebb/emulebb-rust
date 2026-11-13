package org.emulebb.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Runs after unlock; force-stop suppresses delivery according to Android rules. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val prefs = context.getSharedPreferences(DaemonService.PREFERENCES, Context.MODE_PRIVATE)
        val enabled = ServiceRecovery.mayResume(context)
        val allowed = when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> prefs.getBoolean(DaemonService.BOOT, false)
            Intent.ACTION_MY_PACKAGE_REPLACED -> true
            else -> false
        }
        if (enabled && allowed) {
            context.startForegroundService(Intent(context, DaemonService::class.java).setAction(DaemonService.RESUME))
        }
    }
}
