package org.emulebb.android

import android.Manifest
import android.app.Activity
import android.app.ActivityManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.PersistableBundle
import android.os.PowerManager
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.view.WindowInsets
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.util.concurrent.Executors

/** Bootstrap and service control only. Client operations belong to the browser WebUI. */
class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private val setup = Executors.newSingleThreadExecutor()
    private var remote: Messenger? = null
    private var bound = false
    private var resumed = false
    private var busy = true
    private var phase = "Stopped"
    private var address: String? = null
    private var pendingLink: String? = null
    private var pendingLinkError = ""
    private var sharingDiagnostics = false
    private lateinit var status: TextView
    private lateinit var error: TextView
    private lateinit var networkWait: TextView
    private lateinit var permissions: TextView
    private lateinit var pending: TextView
    private lateinit var linkError: TextView
    private lateinit var discardLink: Button
    private lateinit var bind: EditText
    private lateinit var key: EditText
    private lateinit var start: Button
    private lateinit var stop: Button
    private lateinit var save: Button
    private lateinit var regenerate: Button
    private lateinit var open: Button
    private lateinit var shareDiagnostics: Button

    private val replies = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            if (message.what != DaemonService.STATUS) return
            phase = message.data.getString("phase") ?: "Stopped"
            address = message.data.getString("address")
            status.show(phase)
            networkWait.show(if (message.data.getBoolean("waitingForNetwork")) "Waiting for a usable default network" else "")
            error.show(message.data.getString("error") ?: "")
            updateControls()
        }
    })

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            remote = Messenger(service)
            queryStatus()
        }
        override fun onServiceDisconnected(name: ComponentName) {
            remote = null
            phase = "Starting"
            status.text = "Service connection interrupted"
            updateControls()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The setup screen deliberately shows credentials; keep them out of
        // screenshots, recent-task previews, autofill and saved instance state.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val panel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val padding = (16 * resources.displayMetrics.density).toInt()
            setPadding(padding, padding, padding, padding)
        }
        fun label(text: String, id: Int = View.NO_ID) = TextView(this).apply {
            this.text = text; this.id = id; panel.addView(this)
        }
        fun edit(label: String, id: Int) = EditText(this).apply {
            this.id = id
            hint = label
            contentDescription = label
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            isSingleLine = true
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            panel.addView(this)
        }
        fun button(text: String, id: Int = View.NO_ID, action: () -> Unit) = Button(this).apply {
            this.text = text; this.id = id; setOnClickListener { action() }; panel.addView(this)
        }
        label("eMuleBB ${BuildConfig.VERSION_NAME}", R.id.app_version)
        status = label("Stopped", R.id.service_status)
        error = label("")
        networkWait = label("", R.id.network_wait_status)
        permissions = label("")
        pending = label("", R.id.pending_link)
        linkError = label("", R.id.pending_link_error)
        discardLink = button("Discard pending link") {
            pendingLink = null
            pendingLinkError = ""
            updatePendingLink()
        }
        button("Grant all-files access", R.id.grant_all_files_access) {
            launchSettings(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName")))
        }
        button("Allow notifications", R.id.allow_notifications) { requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1) }
        button("Allow local network", R.id.allow_local_network) {
            if (Build.VERSION.SDK_INT >= 37) requestPermissions(arrayOf(DaemonService.LOCAL_NETWORK), 2)
        }.isEnabled = Build.VERSION.SDK_INT >= 37
        button("Allow continuous background operation", R.id.allow_continuous_background) {
            launchSettings(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
        }
        button("App battery settings", R.id.app_battery_settings) {
            launchSettings(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
        }
        label("REST bind address")
        bind = edit("REST bind address", R.id.bind_addr).apply { setText("0.0.0.0:20017") }
        label("API key")
        key = edit("API key", R.id.api_key)
        button("Copy API key", R.id.copy_api_key) {
            val clip = ClipData.newPlainText("eMuleBB API key", key.text.toString())
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
            requireNotNull(getSystemService(ClipboardManager::class.java)).setPrimaryClip(clip)
            Toast.makeText(this, "API key copied", Toast.LENGTH_SHORT).show()
        }
        regenerate = button("Regenerate API key") { key.setText(ShellFiles.newKey()) }
        save = button("Save settings", R.id.save_settings) { saveSettings(false) }
        label("Starting enables the eD2K/Kad peer service; new profiles connect automatically. Incoming files are shared automatically.")
        label("New-profile folders:\nCompleted and shared: ${ShellFiles.defaultIncoming()}\nAdditional sharing: ${ShellFiles.defaultShared()}\nIncomplete files stay in app-managed storage. Manage current folders in WebUI Settings and Sharing; changes are preserved.", R.id.storage_paths)
        start = button("Start", R.id.start_service) { saveSettings(true) }
        stop = button("Stop", R.id.stop_service) {
            phase = "Stopping"
            status.text = phase
            updateControls()
            startService(Intent(this, DaemonService::class.java).setAction(DaemonService.STOP))
        }
        open = button("Open WebUI", R.id.open_webui) {
            address?.let { endpoint ->
                try {
                    val uri = Uri.parse(ShellFiles.browserUrl(endpoint)).buildUpon().apply {
                        pendingLink?.let { link ->
                            path("/transfers")
                            encodedFragment("ed2k=" + Uri.encode(link))
                        }
                    }.build()
                    startActivity(Intent(Intent.ACTION_VIEW, uri))
                    pendingLink = null
                    updatePendingLink()
                }
                catch (_: android.content.ActivityNotFoundException) { error.text = "Install a browser to open the WebUI" }
            }
        }
        label("Share version, service and Android details plus up to 200 recent log summaries. Keys, configuration, paths, peer/content data and free-form messages are excluded.")
        shareDiagnostics = button("Share diagnostics", R.id.share_diagnostics) { shareDiagnosticReport() }
        label("Client settings, sharing, transfers and diagnostics are available in the WebUI. Copy the API key into its sign-in screen.")
        label("Continuous operation uses battery and network traffic. All-files access is required; notifications and battery exemption are recommended.")
        val scroll = ScrollView(this).apply { addView(panel) }
        window.setDecorFitsSystemWindows(false)
        scroll.setOnApplyWindowInsetsListener { view, insets ->
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout() or WindowInsets.Type.ime())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        setContentView(scroll)
        scroll.requestApplyInsets()
        if (savedInstanceState != null) {
            pendingLink = savedInstanceState.getString("pending-link")
            pendingLinkError = savedInstanceState.getString("pending-link-error") ?: ""
            updatePendingLink()
        } else acceptLink(intent)
        updateControls()
        setup.execute {
            try {
                var settings = ShellFiles.readSettings(this)
                if (settings == null) {
                    ShellFiles.saveSettings(this, "0.0.0.0:20017", ShellFiles.newKey(), ShellFiles.prepareWebui(this))
                    settings = ShellFiles.readSettings(this)
                }
                val loaded = requireNotNull(settings)
                handler.post {
                    if (!isDestroyed) {
                        bind.setText(loaded.getString("bind_addr"))
                        key.setText(loaded.getString("api_key"))
                        busy = false
                        updateControls()
                    }
                }
            } catch (failure: Exception) {
                handler.post {
                    if (!isDestroyed) {
                        busy = false
                        error.text = failure.message ?: "Cannot load bootstrap settings"
                        updateControls()
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        acceptLink(intent)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("pending-link", pendingLink)
        outState.putString("pending-link-error", pendingLinkError)
        super.onSaveInstanceState(outState)
    }

    private fun acceptLink(intent: Intent?) {
        if (intent?.action == Intent.ACTION_VIEW) {
            pendingLink = null
            pendingLinkError = ""
            try {
                val raw = requireNotNull(intent.dataString)
                require(raw.length <= 2048)
                pendingLink = NativeBridge.call("validateLink", "link" to raw) as String
            } catch (_: Exception) { pendingLinkError = "Unsupported or malformed eD2K file link" }
        }
        updatePendingLink()
    }

    private fun updatePendingLink() {
        pending.show(pendingLink?.let { "Pending link: $it\nStart the service, then Open WebUI to review and add this file." } ?: "")
        linkError.show(pendingLinkError)
        discardLink.visibility = if (pendingLink != null || pendingLinkError.isNotEmpty()) View.VISIBLE else View.GONE
    }

    private fun TextView.show(value: String) {
        // Avoid recurring accessibility changes while the service state is unchanged.
        if (text.toString() != value) text = value
    }

    private fun launchSettings(intent: Intent) {
        try { startActivity(intent) }
        catch (_: android.content.ActivityNotFoundException) { error.text = "This device does not expose the requested permission settings" }
    }

    private fun shareDiagnosticReport() {
        if (sharingDiagnostics) return
        sharingDiagnostics = true
        shareDiagnostics.isEnabled = false
        val phaseAtRequest = phase
        setup.execute {
            try {
                val uri = DiagnosticsSharing.prepare(this, phaseAtRequest)
                handler.post {
                    if (!isDestroyed) {
                        sharingDiagnostics = false
                        shareDiagnostics.isEnabled = true
                        if (resumed) {
                            val send = Intent(Intent.ACTION_SEND).apply {
                                type = "application/zip"
                                putExtra(Intent.EXTRA_STREAM, uri)
                                clipData = ClipData.newUri(contentResolver, "eMuleBB diagnostics", uri)
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }
                            try { startActivity(Intent.createChooser(send, "Share eMuleBB diagnostics")) }
                            catch (_: android.content.ActivityNotFoundException) { error.show("No application can receive this diagnostic report") }
                        } else error.show("Return to the app and share diagnostics again")
                    }
                }
            } catch (failure: Exception) {
                handler.post {
                    if (!isDestroyed) {
                        sharingDiagnostics = false
                        shareDiagnostics.isEnabled = true
                        error.show("Cannot prepare diagnostics (${failure.javaClass.simpleName})")
                    }
                }
            }
        }
    }

    private fun saveSettings(andStart: Boolean) {
        if (busy || phase !in listOf("Stopped", "Failed")) return
        if (andStart && !Environment.isExternalStorageManager()) {
            error.text = "Grant all-files access before starting"
            return
        }
        if (andStart && Build.VERSION.SDK_INT >= 37 && checkSelfPermission(DaemonService.LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED) {
            error.text = "Allow local-network access before starting"
            return
        }
        val bindValue = bind.text.toString().trim()
        val keyValue = key.text.toString()
        busy = true
        error.text = ""
        updateControls()
        setup.execute {
            try {
                ShellFiles.saveSettings(this, bindValue, keyValue, ShellFiles.prepareWebui(this))
                handler.post {
                    if (!isDestroyed) {
                        busy = false
                        if (andStart && resumed) {
                            try {
                                startForegroundService(Intent(this, DaemonService::class.java).setAction(DaemonService.START))
                                phase = "Starting"
                                status.text = phase
                            } catch (failure: Exception) { error.text = failure.message ?: "Cannot start service" }
                        } else if (andStart) error.text = "Return to the app and press Start"
                        updateControls()
                    }
                }
            } catch (failure: Exception) {
                handler.post { if (!isDestroyed) { busy = false; error.text = failure.message; updateControls() } }
            }
        }
    }

    private fun updateControls() {
        val stopped = phase == "Stopped" || phase == "Failed"
        bind.isEnabled = !busy && stopped
        key.isEnabled = !busy && stopped
        regenerate.isEnabled = !busy && stopped
        save.isEnabled = !busy && stopped
        start.isEnabled = !busy && stopped
        stop.isEnabled = phase == "Starting" || phase == "Running"
        open.isEnabled = phase == "Running" && address != null
    }

    private fun queryStatus() {
        try { remote?.send(Message.obtain(null, DaemonService.STATUS).apply { replyTo = replies }) }
        catch (_: android.os.RemoteException) { remote = null }
    }
    private val poll = object : Runnable {
        override fun run() {
            queryStatus()
            val notifications = checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
            val exemption = requireNotNull(getSystemService(PowerManager::class.java)).isIgnoringBatteryOptimizations(packageName)
            val local = Build.VERSION.SDK_INT < 37 || checkSelfPermission(DaemonService.LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED
            val restricted = requireNotNull(getSystemService(ActivityManager::class.java)).isBackgroundRestricted
            permissions.show("Files: ${if (Environment.isExternalStorageManager()) "allowed" else "required"}; local network: ${if (local) "allowed" else "required"}; notifications: ${if (notifications) "allowed" else "disabled"}; battery exemption: ${if (exemption) "allowed" else "disabled"}; background restriction: ${if (restricted) "enabled" else "disabled"}")
            handler.postDelayed(this, 1_000)
        }
    }

    override fun onStart() {
        super.onStart()
        bound = bindService(Intent(this, DaemonService::class.java), connection, Context.BIND_AUTO_CREATE)
    }
    override fun onResume() { super.onResume(); resumed = true; handler.post(poll) }
    override fun onPause() { resumed = false; handler.removeCallbacks(poll); super.onPause() }
    override fun onStop() {
        if (bound) { unbindService(connection); bound = false; remote = null }
        super.onStop()
    }
    override fun onDestroy() { handler.removeCallbacksAndMessages(null); setup.shutdown(); super.onDestroy() }
}
