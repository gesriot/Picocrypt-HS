package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context

fun AppError.localizedMessage(context: Context): String {
    val id = messageResId ?: return userMessage
    return if (messageArgs.isEmpty()) {
        context.getString(id)
    } else {
        context.getString(id, *messageArgs.toTypedArray())
    }
}
