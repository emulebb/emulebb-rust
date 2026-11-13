package org.emulebb.android

import org.json.JSONObject

/** Private, in-process JNI protocol. Never expose it through an Android component. */
internal object NativeBridge {
    private val loadFailure = try {
        System.loadLibrary("emulebb_android")
        null
    } catch (_: LinkageError) { "Cannot load the packaged native daemon" }
    private external fun request(payload: String): String
    fun isAvailable(): Boolean = loadFailure == null

    fun call(op: String, vararg fields: Pair<String, Any>): Any? {
        check(loadFailure == null) { requireNotNull(loadFailure) }
        val input = JSONObject().put("op", op)
        fields.forEach { input.put(it.first, it.second) }
        val output = JSONObject(request(input.toString()))
        check(output.getBoolean("ok")) { output.optString("error", "Native operation failed") }
        return output.opt("data").takeUnless { it === JSONObject.NULL }
    }
}
