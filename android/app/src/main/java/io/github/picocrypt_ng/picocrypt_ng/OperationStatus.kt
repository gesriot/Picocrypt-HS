package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import androidx.annotation.StringRes

object OperationStatus {
    const val STARTING = "Starting..."
    const val COMPLETED = "Completed"
    const val CANCELLED = "Cancelled"
    const val ERROR = "Error"
}

@StringRes
fun operationStatusMessageResId(status: String): Int? = when (status) {
    OperationStatus.STARTING -> R.string.status_starting
    OperationStatus.COMPLETED -> R.string.status_completed
    OperationStatus.CANCELLED -> R.string.status_cancelled
    OperationStatus.ERROR -> R.string.status_error
    else -> null
}

fun localizedOperationStatus(context: Context, status: String): String {
    if (status.isEmpty()) return context.getString(R.string.unknown)
    val messageResId = operationStatusMessageResId(status) ?: return status
    return context.getString(messageResId)
}
