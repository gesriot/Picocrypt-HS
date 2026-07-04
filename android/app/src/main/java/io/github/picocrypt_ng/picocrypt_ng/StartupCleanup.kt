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
            if (cleanupDoneInThisProcess) {
                false
            } else {
                cleanupDoneInThisProcess = true
                true
            }
        }

        if (!shouldRunCleanup) return true

        return runBlocking {
            cleanup(context)
        }
    }

    internal fun resetForTests() {
        synchronized(lock) {
            cleanupDoneInThisProcess = false
        }
    }
}
