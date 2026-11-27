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
import android.net.LinkProperties
import java.net.Inet4Address
import java.net.InetAddress
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
        // JNI daemon ownership is process-wide. A replacement service's first
        // command must run after any teardown queued by the old instance.
        private val commands = Executors.newSingleThreadExecutor()
        const val STOP_REQUEST = "stopRequest"
        const val STATUS = 1
        const val PREFERENCES = "service-lifecycle"
        const val DESIRED = "desired-running"
        const val LOCAL_NETWORK = Manifest.permission.ACCESS_LOCAL_NETWORK
        private const val CHANNEL = "daemon"
        private const val NOTICE = 1
    }

    private fun hasLocalNetworkPermission() = Build.VERSION.SDK_INT < 37 ||
        checkSelfPermission(LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED

    private data class Ipv4Route(
        val addresses: Set<Inet4Address>,
        val interfaceName: String?,
        val defaultGateways: Set<InetAddress?>,
    )

    private val handler = Handler(Looper.getMainLooper())
    private val desired = AtomicBoolean(false)
    private val networkNotificationPending = AtomicBoolean(false)
    private val prefs by lazy { getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE) }
    private var phase = "Stopped"
    private var error: String? = null
    private var address: String? = null
    private var starting = false
    private var wakeLock: PowerManager.WakeLock? = null
    private var network: Network? = null
    private var routeIpv4: Ipv4Route? = null
    private var publicIpv4: String? = null
    private var confirmedStopped = false
    private var stopRequest: String? = null
    private var stopCommandPending = false
    private var restartForNetwork = false
    private var stopFailures = 0
    private var statusFailures = 0
    private var notifiedPhase: String? = null
    private var waitingForNetwork = false
    private var destroyed = false
    private val connectivity by lazy { requireNotNull(getSystemService(ConnectivityManager::class.java)) }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(available: Network) {
            handler.post {
                if (destroyed || available == network) return@post
                network = available
                routeIpv4 = null
                defaultRouteChanged()
            }
        }

        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            val route = Ipv4Route(
                properties.linkAddresses.mapNotNull { it.address as? Inet4Address }.toSet(),
                properties.interfaceName,
                properties.routes.filter { it.isDefaultRoute && it.destination.address is Inet4Address }
                    .map { it.gateway }.toSet(),
            )
            handler.post {
                if (destroyed || this@DaemonService.network != network) return@post
                val previous = routeIpv4
                routeIpv4 = route
                if (previous != null && previous != route) defaultRouteChanged()
                else notifyNetworkChanged()
            }
        }

        override fun onLost(network: Network) {
            handler.post {
                if (destroyed || this@DaemonService.network != network) return@post
                this@DaemonService.network = null
                routeIpv4 = null
                defaultRouteChanged()
            }
        }
    }

    private fun defaultRouteChanged() {
        publicIpv4 = null
        recordEvent(AndroidSupportLog.Event.NETWORK_CHANGED)
        notifyNetworkChanged()
        if (desired.get() && (phase == "Running" || (phase == "Starting" && !waitingForNetwork))) {
            restartForNetwork = true
            phase = "Stopping"
            requestNativeStop()
        }
    }

    private fun recordEvent(event: AndroidSupportLog.Event) {
        AndroidSupportLog.enqueue(this, System.currentTimeMillis(), event)
    }

    private fun notifyNetworkChanged() {
        if (destroyed || !desired.get()) return
        if (!networkNotificationPending.compareAndSet(false, true)) return
        commands.execute {
            // Coalesce callbacks while setup occupies the command executor.
            // Reset before JNI so an event racing this call retains a final wake.
            networkNotificationPending.set(false)
            try { if (desired.get()) NativeBridge.call("networkChanged") }
            catch (failure: Exception) {
                handler.post { if (!destroyed && desired.get()) fail(failure.message ?: "Cannot notify native network change") }
            }
        }
    }

    private val messenger = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            // The service is non-exported; Binder calls remain within this application's UID.
            if (!destroyed && message.what == STATUS) {
                val response = Message.obtain(null, STATUS).apply {
                    data = Bundle().apply {
                        putString("phase", phase)
                        putString("error", error)
                        putString("address", address)
                        putString("publicIpv4", publicIpv4.takeIf { phase == "Running" })
                        putBoolean("confirmedStopped", confirmedStopped)
                        putString("stopRequest", stopRequest)
                        putBoolean("stopFailed", stopFailures >= 3 || statusFailures >= 3 || phase == "Failed")
                        putBoolean("waitingForNetwork", waitingForNetwork)
                    }
                }
                try { message.replyTo?.send(response) } catch (_: android.os.RemoteException) { }
            }
        }
    })

    override fun onCreate() {
        super.onCreate()
        confirmedStopped = !ServiceRecovery.mayResume(this)
        error = prefs.getString("last-error", null)
        if (error != null) phase = "Failed"
        requireNotNull(getSystemService(NotificationManager::class.java)).createNotificationChannel(
            NotificationChannel(CHANNEL, "eMuleBB service", NotificationManager.IMPORTANCE_LOW))
        network = connectivity.activeNetwork
        connectivity.registerDefaultNetworkCallback(networkCallback)
    }

    override fun onBind(intent: Intent): IBinder = messenger.binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            stopExplicitly(intent.getStringExtra(STOP_REQUEST))
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
        confirmedStopped = false
        stopRequest = null
        recordEvent(AndroidSupportLog.Event.START_REQUESTED)
        error = null
        stopFailures = 0
        statusFailures = 0
        try {
            val foregroundType = if (Build.VERSION.SDK_INT >= 34) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            } else {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_NONE
            }
            startForeground(NOTICE, notification("Starting"), foregroundType)
            notifiedPhase = "Starting"
        } catch (failure: Exception) {
            // Promotion happens before native startup. A platform/AppOp denial
            // must be visible rather than becoming an automatic crash loop.
            error = "Android refused the foreground service: ${failure.javaClass.simpleName}"
            confirmedStopped = setDesired(false)
            phase = "Failed"
            recordEvent(AndroidSupportLog.Event.START_FAILED)
            prefs.edit().putString("last-error", error).commit()
            releaseWakeLock()
            stopSelf()
            return START_NOT_STICKY
        }
        if (!Environment.isExternalStorageManager()) {
            fail("All-files access is required. Open the app to grant it.")
            return START_NOT_STICKY
        }
        if (!hasLocalNetworkPermission()) {
            fail("Local-network permission is required. Open the app to grant it.")
            return START_NOT_STICKY
        }
        if (wakeLock == null) {
            wakeLock = requireNotNull(getSystemService(PowerManager::class.java)).newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK, "$packageName:continuous-service").apply {
                setReferenceCounted(false)
                acquire()
            }
        }
        if (!starting && phase != "Running" && phase != "Stopping") {
            phase = "Starting"
            val delay = if (intent?.action == START) 0L else (1L shl prefs.getInt("restarts", 1)) * 1_000
            handler.postDelayed({ if (!destroyed && desired.get() && !starting) startNative() }, delay)
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
                var nativeDraining = false
                if (desired.get()) {
                    val nativePhase = (NativeBridge.call("status") as JSONObject).getString("phase")
                    nativeDraining = nativePhase == "Stopping"
                    if (!nativeDraining) {
                        ShellFiles.prepareStart(this)
                        // Stop can cancel preparation before it enters JNI.
                        if (desired.get()) ShellFiles.start(this)
                    }
                }
                handler.post {
                    if (destroyed) return@post
                    starting = false
                    if (nativeDraining && desired.get()) {
                        handler.postDelayed({
                            if (!destroyed && desired.get() && !starting && !stopCommandPending) {
                                startNative()
                            }
                        }, 1_000)
                    } else {
                        handler.removeCallbacks(poll)
                        handler.post(poll)
                    }
                }
            } catch (failure: Exception) {
                handler.post {
                    if (destroyed) return@post
                    starting = false
                    recordEvent(AndroidSupportLog.Event.START_FAILED)
                    fail(failure.message ?: "Service startup failed")
                }
            }
        }
    }

    private val poll = object : Runnable {
        override fun run() {
            if (destroyed) return
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
                if (starting || stopCommandPending) {
                    handler.postDelayed(this, 1_000)
                    return
                }
                val status = NativeBridge.call("status") as JSONObject
                val nextPhase = status.getString("phase")
                statusFailures = 0
                if (phase != "Running" && nextPhase == "Running" && desired.get() && !restartForNetwork) {
                    recordEvent(AndroidSupportLog.Event.RUNNING)
                }
                phase = nextPhase
                publicIpv4 = status.optString("publicIpv4").takeUnless {
                    it.isEmpty() || it == "null" || network == null || !desired.get() || restartForNetwork
                }
                waitingForNetwork = status.getBoolean("waitingForNetwork")
                address = status.optString("address").takeUnless { it.isEmpty() || it == "null" }
                if (phase == "Failed") {
                    error = status.optString("error").takeUnless { it.isBlank() || it == "null" }
                        ?: error ?: "Native runtime failed"
                    finishStopped()
                    return
                }
                if ((!desired.get() || restartForNetwork) && (phase == "Running" || phase == "Starting")) {
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
                val noticeState = if (waitingForNetwork) "Waiting for network" else phase
                if (notifiedPhase != noticeState) {
                    requireNotNull(getSystemService(NotificationManager::class.java)).notify(NOTICE, notification(noticeState))
                    notifiedPhase = noticeState
                }
                handler.postDelayed(this, 1_000)
            } catch (failure: Exception) {
                statusFailures = (statusFailures + 1).coerceAtMost(3)
                error = failure.message ?: "Cannot inspect native runtime"
                setDesired(false)
                restartForNetwork = false
                phase = "Stopping"
                if (!NativeBridge.isAvailable()) finishStopped()
                else {
                    // Unknown native state is not Stopped. Retain the foreground
                    // owner until JNI reports drained; never start a second core.
                    if (statusFailures >= 3 || stopFailures >= 3) {
                        error = "Native shutdown could not be confirmed. Use Android app settings to force-stop eMuleBB."
                    } else if (statusFailures == 1) {
                        requestNativeStop()
                    }
                    handler.postDelayed(this, 1_000)
                }
            }
        }
    }

    private fun setDesired(enabled: Boolean): Boolean {
        desired.set(enabled)
        val saved = prefs.edit().putBoolean(DESIRED, enabled).commit()
        if (!saved) error = "Cannot persist service state"
        return saved
    }

    private fun stopExplicitly(request: String?) {
        if (request != null) {
            if (request == stopRequest) return
            stopRequest = request
        }
        recordEvent(AndroidSupportLog.Event.STOP_REQUESTED)
        setDesired(false)
        restartForNetwork = false
        confirmedStopped = false
        stopFailures = 0
        statusFailures = 0
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
        if (stopCommandPending) return
        stopCommandPending = true
        commands.execute {
            try { NativeBridge.call("stop") }
            catch (failure: Exception) {
                handler.post {
                    if (destroyed) return@post
                    stopFailures++
                    error = failure.message ?: "Native Stop failed"
                }
            }
            handler.post {
                if (destroyed) return@post
                stopCommandPending = false
                handler.removeCallbacks(poll)
                handler.post(poll)
            }
        }
    }

    private fun finishStopped() {
        val persisted = setDesired(false)
        confirmedStopped = persisted
        phase = if (error == null) "Stopped" else "Failed"
        publicIpv4 = null
        recordEvent(if (error == null) AndroidSupportLog.Event.STOPPED else AndroidSupportLog.Event.RUNTIME_FAILED)
        waitingForNetwork = false
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
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("eMuleBB: $state")
            .setContentText("Continuous eD2K/Kad peer service")
            .setContentIntent(open).setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build()).build()
    }

    override fun onDestroy() {
        destroyed = true
        desired.set(false)
        handler.removeCallbacksAndMessages(null)
        connectivity.unregisterNetworkCallback(networkCallback)
        // Deliberately retain desired-running on OS teardown. Explicit Stop and
        // graceful REST shutdown clear it before entering this path.
        commands.execute { try { NativeBridge.call("stop") } catch (_: Exception) { } }
        releaseWakeLock()
        super.onDestroy()
    }
}
