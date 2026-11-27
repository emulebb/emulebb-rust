package org.emulebb.android

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.time.Instant
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** The daemon service is the sole writer. The setup activity reads immutable snapshots. */
internal object AndroidSupportLog {
    enum class Event(val code: String) {
        START_REQUESTED("start_requested"),
        RUNNING("running"),
        START_FAILED("start_failed"),
        NETWORK_CHANGED("network_changed"),
        STOP_REQUESTED("stop_requested"),
        STOPPED("stopped"),
        RUNTIME_FAILED("runtime_failed")
    }

    private const val MAX_RECORDS = 100
    private const val MAX_BYTES = 16L * 1024
    // A slow log rewrite must never delay daemon commands, or accumulate an
    // unbounded backlog during network churn. Keep the newest pending events.
    private val writer = ThreadPoolExecutor(
        1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(8),
        ThreadPoolExecutor.DiscardOldestPolicy(),
    )

    fun enqueue(context: Context, time: Long, event: Event) {
        val app = context.applicationContext
        writer.execute { record(app, time, event) }
    }

    private fun log(context: Context) = File(context.filesDir, "android-support-events.jsonl")

    private fun record(context: Context, time: Long, event: Event) {
        val destination = log(context)
        val temporary = File(destination.parentFile, "android-support-events.tmp")
        try {
            val entries = read(context).takeLast(MAX_RECORDS - 1) + entry(time, event)
            temporary.writeText(encode(entries))
            // Readers see a complete snapshot even if the service dies during an update.
            Files.move(temporary.toPath(), destination.toPath(), StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING)
        } catch (_: Exception) {
            temporary.delete()
        }
    }

    fun bytes(context: Context): ByteArray = encode(read(context)).toByteArray(Charsets.UTF_8)

    private fun read(context: Context): List<JSONObject> {
        val file = log(context)
        if (!file.isFile || Files.isSymbolicLink(file.toPath()) || file.length() > MAX_BYTES) return emptyList()
        return try {
            file.useLines { lines ->
                lines.take(MAX_RECORDS).mapNotNull { line ->
                    try {
                        val raw = JSONObject(line)
                        val time = Instant.parse(raw.getString("timestamp")).toEpochMilli()
                        Event.entries.firstOrNull { it.code == raw.optString("event") }?.let { entry(time, it) }
                    } catch (_: Exception) { null }
                }.toList()
            }
        } catch (_: java.io.IOException) {
            emptyList()
        }
    }

    private fun entry(time: Long, event: Event) = JSONObject().apply {
        put("timestamp", Instant.ofEpochMilli(time).toString())
        put("event", event.code)
    }

    private fun encode(entries: List<JSONObject>): String = entries.joinToString("") { "$it\n" }
}
