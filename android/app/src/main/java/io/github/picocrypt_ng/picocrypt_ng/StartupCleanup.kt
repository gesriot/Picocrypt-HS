package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal object StartupCleanup {
    private val lock = Mutex()
    private var cleanupDoneInThisProcess = false

    suspend fun runBeforeUi(
        context: Context,
        cleanup: suspend (Context) -> Boolean = FileCopyService::cleanupAllFiles,
    ): Boolean = lock.withLock {
        if (cleanupDoneInThisProcess) return@withLock true

        val cleanupSucceeded = cleanup(context)
        if (cleanupSucceeded) {
            cleanupDoneInThisProcess = true
        }
        cleanupSucceeded
    }

    internal fun resetForTests() {
        cleanupDoneInThisProcess = false
    }
}
