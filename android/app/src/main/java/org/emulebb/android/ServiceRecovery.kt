package org.emulebb.android

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context

/** Android's Active apps Stop kills the process without any service callback. */
internal object ServiceRecovery {
    const val LAST_EXPLICIT_START = "last-explicit-start"

    fun mayResume(context: Context): Boolean {
        val prefs = context.getSharedPreferences(DaemonService.PREFERENCES, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(DaemonService.DESIRED, false)) return false
        val started = prefs.getLong(LAST_EXPLICIT_START, 0)
        val exits = requireNotNull(context.getSystemService(ActivityManager::class.java))
            .getHistoricalProcessExitReasons(context.packageName, 0, 0)
        val stoppedByUser = exits.any {
            it.processName == "${context.packageName}:daemon" &&
                it.reason == ApplicationExitInfo.REASON_USER_REQUESTED && it.timestamp >= started
        }
        if (stoppedByUser) {
            // Only daemon-process exits count: dismissing the setup activity's
            // task must not cancel a user-enabled foreground peer service.
            prefs.edit().putBoolean(DaemonService.DESIRED, false).commit()
            return false
        }
        return true
    }
}
