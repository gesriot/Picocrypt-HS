package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import io.mockk.mockk
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class StartupCleanupTest {
    private lateinit var context: Context

    @Before
    fun setUp() {
        context = mockk(relaxed = true)
        StartupCleanup.resetForTests()
    }

    @After
    fun tearDown() {
        StartupCleanup.resetForTests()
    }

    @Test
    fun runBeforeUi_isSuspendApiWithoutRunBlocking() {
        val suspendMethod = StartupCleanup::class.java.declaredMethods.any { method ->
            method.name == "runBeforeUi" &&
                method.parameterTypes.lastOrNull()?.name == "kotlin.coroutines.Continuation"
        }

        assertTrue("Startup cleanup must be a suspend API so MainActivity cannot call it directly on the UI thread", suspendMethod)

        val source = File("../app/src/main/java/io/github/picocrypt_ng/picocrypt_ng/StartupCleanup.kt")
            .readText()
        assertFalse("Startup cleanup must not use runBlocking from Activity startup", source.contains("runBlocking"))
    }

    @Test
    fun runBeforeUi_waitsForCleanupToFinishBeforeReturning() = runTest {
        val cleanupStarted = CompletableDeferred<Unit>()
        val allowCleanupToFinish = CompletableDeferred<Unit>()
        val returned = AtomicBoolean(false)

        val cleanupJob = async {
            StartupCleanup.runBeforeUi(context) {
                cleanupStarted.complete(Unit)
                allowCleanupToFinish.await()
                true
            }
            returned.set(true)
        }

        cleanupStarted.await()
        assertFalse("UI gate must not return while cleanup is still running", returned.get())

        allowCleanupToFinish.complete(Unit)
        cleanupJob.await()

        assertTrue("UI gate should return after cleanup completes", returned.get())
    }

    @Test
    fun runBeforeUi_runsCleanupOnlyOncePerProcessReset() = runTest {
        val cleanupRuns = AtomicInteger(0)

        StartupCleanup.runBeforeUi(context) {
            cleanupRuns.incrementAndGet()
            true
        }
        StartupCleanup.runBeforeUi(context) {
            cleanupRuns.incrementAndGet()
            true
        }

        assertEquals("Startup cleanup should run once per process", 1, cleanupRuns.get())

        StartupCleanup.resetForTests()
        StartupCleanup.runBeforeUi(context) {
            cleanupRuns.incrementAndGet()
            true
        }

        assertEquals("Test reset should simulate a fresh process", 2, cleanupRuns.get())
    }

    @Test
    fun runBeforeUi_retriesAfterCleanupFailure() = runTest {
        val cleanupRuns = AtomicInteger(0)

        val firstResult = StartupCleanup.runBeforeUi(context) {
            cleanupRuns.incrementAndGet()
            false
        }
        val secondResult = StartupCleanup.runBeforeUi(context) {
            cleanupRuns.incrementAndGet()
            true
        }

        assertFalse("Failed cleanup should be reported", firstResult)
        assertTrue("Second cleanup attempt should be allowed to succeed", secondResult)
        assertEquals("Failed cleanup must not be marked done for the process", 2, cleanupRuns.get())
    }
}
