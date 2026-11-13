package org.emulebb.android

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.os.Bundle
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.PowerManager
import android.os.SystemClock
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Owns service intent and the native runtime; no client settings are duplicated here. */
class DaemonService : Service() {
    companion object {
        const val START = "org.emulebb.android.START"
        const val STOP = "org.emulebb.android.STOP"
        const val RESUME = "org.emulebb.android.RESUME"
        const val STATUS = 1
        const val SET_BOOT_RESUME = 2
        const val PREFERENCES = "service-lifecycle"
        const val DESIRED = "desired-running"
        const val BOOT = "resume-on-boot"
        const val LOCAL_NETWORK = Manifest.permission.ACCESS_LOCAL_NETWORK
        private const val CHANNEL = "daemon"
        private const val NOTICE = 1
    }

    private fun hasLocalNetworkPermission() = Build.VERSION.SDK_INT < 37 ||
        checkSelfPermission(LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED

    private val handler = Handler(Looper.getMainLooper())
    private val commands = Executors.newSingleThreadExecutor()
    private val desired = AtomicBoolean(false)
    private val prefs by lazy { getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE) }
    private var phase = "Stopped"
    private var error: String? = null
    private var address: String? = null
    private var starting = false
    private var wakeLock: PowerManager.WakeLock? = null
    private var network: Network? = null
    private var restartForNetwork = false
    private var stopFailures = 0
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(available: Network) {
            handler.post {
                val changed = network != null && network != available
                network = available
                if (changed && desired.get() && phase == "Running") {
                    restartForNetwork = true
                    phase = "Stopping"
                    requestNativeStop()
                }
            }
        }
    }

    private val messenger = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            // The service is non-exported; Binder calls remain within this application's UID.
            if (message.what == SET_BOOT_RESUME) {
                if (!prefs.edit().putBoolean(BOOT, message.arg1 != 0).commit()) {
                    error = "Cannot save reboot preference"
                }
            }
            if (message.what == STATUS || message.what == SET_BOOT_RESUME) {
                val response = Message.obtain(null, STATUS).apply {
                    data = Bundle().apply {
                        putString("phase", phase)
                        putString("error", error)
                        putString("address", address)
                        putBoolean("resumeOnBoot", prefs.getBoolean(BOOT, false))
                    }
                }
                try { message.replyTo?.send(response) } catch (_: android.os.RemoteException) { }
            }
        }
    })

    override fun onCreate() {
        super.onCreate()
        error = prefs.getString("last-error", null)
        if (error != null) phase = "Failed"
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, "eMuleBB service", NotificationManager.IMPORTANCE_LOW))
        network = connectivity.activeNetwork
        connectivity.registerDefaultNetworkCallback(networkCallback)
    }

    override fun onBind(intent: Intent): IBinder = messenger.binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            stopExplicitly()
            return START_NOT_STICKY
        }
        if (intent?.action != START && !ServiceRecovery.mayResume(this)) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (intent?.action == START) {
            if (!prefs.edit().putInt("restarts", 0).putLong("restart-window", SystemClock.elapsedRealtime())
                .putLong(ServiceRecovery.LAST_EXPLICIT_START, System.currentTimeMillis()).commit()) {
                fail("Cannot persist explicit service start")
                return START_NOT_STICKY
            }
        } else if (!admitRecovery()) {
            fail("Repeated service termination; open the app and press Start to retry")
            return START_NOT_STICKY
        }
        if (!prefs.edit().putBoolean(DESIRED, true).remove("last-error").commit()) {
            fail("Cannot persist service state")
            return START_NOT_STICKY
        }
        desired.set(true)
        error = null
        stopFailures = 0
        startForeground(NOTICE, notification("Starting"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        if (!Environment.isExternalStorageManager()) {
            fail("All-files access is required. Open the app to grant it.")
            return START_NOT_STICKY
        }
        if (!hasLocalNetworkPermission()) {
            fail("Local-network permission is required. Open the app to grant it.")
            return START_NOT_STICKY
        }
        if (wakeLock == null) {
            wakeLock = getSystemService(PowerManager::class.java).newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK, "$packageName:continuous-service").apply {
                setReferenceCounted(false)
                acquire()
            }
        }
        if (!starting && phase != "Running" && phase != "Stopping") {
            phase = "Starting"
            val delay = if (intent?.action == START) 0L else (1L shl prefs.getInt("restarts", 1)) * 1_000
            handler.postDelayed({ if (desired.get() && !starting) startNative() }, delay)
        }
        return START_STICKY
    }

    private fun admitRecovery(): Boolean {
        val now = SystemClock.elapsedRealtime()
        val window = prefs.getLong("restart-window", now)
        val fresh = now < window || now - window > 600_000
        val attempts = if (fresh) 0 else prefs.getInt("restarts", 0)
        return attempts < 3 && prefs.edit().putInt("restarts", attempts + 1)
            .putLong("restart-window", if (fresh) now else window).commit()
    }

    private fun startNative() {
        starting = true
        phase = "Starting"
        commands.execute {
            try {
                ShellFiles.prepareStart(this)
                // Commands are serialized: Stop queued during preparation runs after
                // any Start already entering JNI, and cancellation before it skips Start.
                if (desired.get()) ShellFiles.start(this)
                handler.post { starting = false; handler.removeCallbacks(poll); handler.post(poll) }
            } catch (failure: Exception) {
                handler.post { starting = false; fail(failure.message ?: "Service startup failed") }
            }
        }
    }

    private val poll = object : Runnable {
        override fun run() {
            try {
                if (!Environment.isExternalStorageManager() && desired.get()) {
                    restartForNetwork = false
                    error = "All-files access was revoked; stopping the daemon"
                    setDesired(false)
                    requestNativeStop()
                }
                if (!hasLocalNetworkPermission() && desired.get()) {
                    restartForNetwork = false
                    error = "Local-network permission was revoked; stopping the daemon"
                    setDesired(false)
                    requestNativeStop()
                }
                val status = NativeBridge.call("status") as JSONObject
                phase = status.getString("phase")
                address = status.optString("address").takeUnless { it.isEmpty() || it == "null" }
                if (phase == "Failed") {
                    error = status.optString("error").takeUnless { it.isBlank() || it == "null" }
                        ?: error ?: "Native runtime failed"
                    finishStopped()
                    return
                }
                if (!desired.get() && (phase == "Running" || phase == "Starting")) {
                    phase = "Stopping"
                    if (stopFailures in 1..2) requestNativeStop()
                    if (stopFailures >= 3) error = "Native Stop failed. Use Android app settings to force-stop eMuleBB."
                }
                if (phase == "Stopped") {
                    if (desired.get() && restartForNetwork) {
                        restartForNetwork = false
                        startNative()
                        return
                    }
                    // A graceful REST shutdown is an explicit stop, too. Process
                    // death never reaches this path, retaining restart intent.
                    finishStopped()
                    return
                }
                getSystemService(NotificationManager::class.java).notify(NOTICE, notification(phase))
                handler.postDelayed(this, 1_000)
            } catch (failure: Exception) {
                error = failure.message ?: "Cannot inspect native runtime"
                setDesired(false)
                restartForNetwork = false
                phase = "Stopping"
                if (!NativeBridge.isAvailable()) finishStopped()
                else {
                    // Unknown native state is not Stopped. Retain the foreground
                    // owner until JNI reports drained; never start a second core.
                    if (stopFailures < 3) requestNativeStop()
                    else error = "Native shutdown could not be confirmed. Use Android app settings to force-stop eMuleBB."
                    handler.postDelayed(this, 1_000)
                }
            }
        }
    }

    private fun setDesired(enabled: Boolean) {
        desired.set(enabled)
        if (!prefs.edit().putBoolean(DESIRED, enabled).commit()) error = "Cannot persist service state"
    }

    private fun stopExplicitly() {
        setDesired(false)
        restartForNetwork = false
        phase = "Stopping"
        requestNativeStop()
    }

    private fun fail(message: String) {
        error = message
        setDesired(false)
        restartForNetwork = false
        phase = "Stopping"
        requestNativeStop()
    }

    private fun requestNativeStop() {
        commands.execute {
            try { NativeBridge.call("stop") }
            catch (failure: Exception) {
                handler.post { stopFailures++; error = failure.message ?: "Native Stop failed" }
            }
            handler.post { handler.removeCallbacks(poll); handler.post(poll) }
        }
    }

    private fun finishStopped() {
        setDesired(false)
        phase = if (error == null) "Stopped" else "Failed"
        if (error != null) prefs.edit().putString("last-error", error).commit()
        releaseWakeLock()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    private fun notification(state: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, DaemonService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("eMuleBB: $state")
            .setContentText("Continuous eD2K/Kad peer service")
            .setContentIntent(open).setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build()).build()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        connectivity.unregisterNetworkCallback(networkCallback)
        // Deliberately retain desired-running on OS teardown. Explicit Stop and
        // graceful REST shutdown clear it before entering this path.
        commands.execute { try { NativeBridge.call("stop") } catch (_: Exception) { } }
        commands.shutdown()
        releaseWakeLock()
        super.onDestroy()
    }
}
