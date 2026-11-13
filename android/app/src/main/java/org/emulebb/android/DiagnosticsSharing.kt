package org.emulebb.android

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.content.FileProvider
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Shares only the daemon's closed diagnostic projection and non-identifying app metadata. */
internal object DiagnosticsSharing {
    private const val MAX_JSON_BYTES = 256 * 1024
    private const val RETAINED_REPORTS = 4
    private val reportName = Regex("emulebb-diagnostics-[0-9a-f-]+\\.zip")

    @Synchronized
    fun prepare(context: Context, phaseAtRequest: String): Uri {
        val diagnostics = NativeBridge.call("shareDiagnostics", "profile_dir" to ShellFiles.profile(context).absolutePath) as JSONObject
        check(diagnostics.getString("schema") == "emulebb.support-diagnostics/1") { "Unexpected diagnostic projection" }
        val phase = phaseAtRequest.takeIf { it in setOf("Stopped", "Starting", "Running", "Stopping", "Failed") } ?: "Unknown"
        val metadata = JSONObject().apply {
            put("schema", "emulebb.android.support-share/1")
            put("versionName", BuildConfig.VERSION_NAME)
            put("versionCode", BuildConfig.VERSION_CODE)
            put("servicePhaseAtRequest", phase)
            put("android", JSONObject().apply {
                put("apiLevel", Build.VERSION.SDK_INT)
                put("release", Build.VERSION.RELEASE)
                put("manufacturer", Build.MANUFACTURER)
                put("model", Build.MODEL)
                put("supported64BitAbis", JSONArray(Build.SUPPORTED_64_BIT_ABIS.toList()))
            })
        }
        val diagnosticBytes = diagnostics.toString().toByteArray(Charsets.UTF_8)
        val metadataBytes = metadata.toString().toByteArray(Charsets.UTF_8)
        check(diagnosticBytes.size <= MAX_JSON_BYTES && metadataBytes.size <= 8192) { "Diagnostic report exceeds its sharing budget" }
        val cache = context.cacheDir.canonicalFile
        val root = File(cache, "diagnostics")
        check(!Files.isSymbolicLink(root.toPath())) { "Diagnostic cache must be owned" }
        check(root.mkdirs() || root.isDirectory) { "Cannot create diagnostic cache" }
        check(root.canonicalFile.parentFile == cache) { "Diagnostic cache escaped app storage" }
        // Cache is private to this app. Bound its own immutable reports and
        // revoke earlier read grants before removing older share files.
        val reports = root.listFiles().orEmpty().filter {
            reportName.matches(it.name) && it.isFile && !Files.isSymbolicLink(it.toPath())
        }.sortedByDescending { it.lastModified() }
        reports.drop(RETAINED_REPORTS - 1).forEach { old ->
            context.revokeUriPermission(uri(context, old), Intent.FLAG_GRANT_READ_URI_PERMISSION)
            check(old.delete()) { "Cannot expire an old diagnostic report" }
        }
        val report = File(root, "emulebb-diagnostics-${UUID.randomUUID()}.zip")
        try {
            ZipOutputStream(Files.newOutputStream(report.toPath(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)).use { zip ->
                for ((name, bytes) in listOf("metadata.json" to metadataBytes, "diagnostics.json" to diagnosticBytes)) {
                    zip.putNextEntry(ZipEntry(name))
                    zip.write(bytes)
                    zip.closeEntry()
                }
            }
            return uri(context, report)
        } catch (failure: Exception) {
            report.delete()
            throw failure
        }
    }

    private fun uri(context: Context, report: File): Uri =
        FileProvider.getUriForFile(context, "${context.packageName}.diagnostics", report)
}
