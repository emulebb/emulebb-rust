package org.emulebb.android

import android.content.Context
import android.os.Environment
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.security.SecureRandom

internal object ShellFiles {
    fun profile(context: Context) = File(context.filesDir, "profile")

    fun newKey(): String = ByteArray(32).also { SecureRandom().nextBytes(it) }
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    /** Assets are immutable per APK version. Cross-process locking prevents partial reads. */
    fun prepareWebui(context: Context): File {
        val root = File(context.filesDir, "webui-${BuildConfig.VERSION_CODE}")
        RandomAccessFile(File(context.filesDir, "webui.lock"), "rw").use { lockFile ->
            lockFile.channel.lock().use {
                val ready = File(root, ".ready")
                if (!ready.isFile) {
                    check(root.mkdirs() || root.isDirectory) { "Cannot create WebUI directory" }
                    copyAssets(context, "webui", root)
                    check(File(root, "index.html").isFile) { "Packaged WebUI is incomplete" }
                    ready.outputStream().use { it.fd.sync() }
                }
            }
        }
        return root
    }

    private fun copyAssets(context: Context, source: String, target: File) {
        val children = context.assets.list(source) ?: error("Missing packaged WebUI")
        if (children.isEmpty()) {
            context.assets.open(source).use { input ->
                target.outputStream().use { output -> input.copyTo(output); output.fd.sync() }
            }
        } else {
            check(target.mkdirs() || target.isDirectory) { "Cannot create WebUI assets" }
            children.forEach { copyAssets(context, "$source/$it", File(target, it)) }
        }
    }

    fun readSettings(context: Context): JSONObject? = NativeBridge.call(
        "readSettings", "profile_dir" to profile(context).absolutePath
    ) as JSONObject?

    fun saveSettings(context: Context, bind: String, key: String, webui: File) {
        NativeBridge.call("writeSettings", "profile_dir" to profile(context).absolutePath,
            "bind_addr" to bind, "api_key" to key, "web_root_dir" to webui.absolutePath)
        NativeBridge.call("pruneAssets", "profile_dir" to profile(context).absolutePath,
            "current_web_root" to webui.absolutePath)
    }

    fun prepareStart(context: Context) {
        val settings = readSettings(context) ?: error("Open eMuleBB and complete setup before starting")
        val webui = prepareWebui(context)
        if (settings.optString("web_root_dir") != webui.absolutePath) {
            saveSettings(context, settings.getString("bind_addr"), settings.getString("api_key"), webui)
        }
    }

    fun start(context: Context) {
        val external = context.getExternalFilesDir(null) ?: error("Payload storage is unavailable")
        val incoming = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "eMuleBB")
        NativeBridge.call("start", "profile_dir" to profile(context).absolutePath,
            "transfer_root" to File(external, "transfers").absolutePath, "incoming_dir" to incoming.absolutePath)
    }

    fun browserUrl(address: String): String {
        val authority = when {
            address.startsWith("0.0.0.0:") -> "127.0.0.1:" + address.substringAfterLast(':')
            address.startsWith("[::]:") -> "[::1]:" + address.substringAfterLast(':')
            else -> address
        }
        return "http://$authority/"
    }
}
