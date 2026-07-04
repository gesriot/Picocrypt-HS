package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import kotlinx.coroutines.runBlocking

internal object StartupCleanup {
    private val lock = Any()
    private var cleanupDoneInThisProcess = false

    fun runBeforeUi(
        context: Context,
        cleanup: suspend (Context) -> Boolean = FileCopyService::cleanupAllFiles,
    ): Boolean {
        val shouldRunCleanup = synchronized(lock) {
            !cleanupDoneInThisProcess
        }

        if (!shouldRunCleanup) return true

        val cleanupSucceeded = runBlocking {
            cleanup(context)
        }
        if (cleanupSucceeded) {
            synchronized(lock) {
                cleanupDoneInThisProcess = true
            }
        }
        return cleanupSucceeded
    }

    internal fun resetForTests() {
        synchronized(lock) {
            cleanupDoneInThisProcess = false
        }
    }
}
