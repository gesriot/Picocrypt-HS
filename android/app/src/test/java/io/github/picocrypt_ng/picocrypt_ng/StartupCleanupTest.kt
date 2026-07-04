package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import io.mockk.mockk
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlinx.coroutines.CompletableDeferred
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
    fun runBeforeUi_waitsForCleanupToFinishBeforeReturning() {
        val cleanupStarted = CountDownLatch(1)
        val allowCleanupToFinish = CompletableDeferred<Unit>()
        val returned = AtomicBoolean(false)

        val cleanupThread = thread(start = true) {
            StartupCleanup.runBeforeUi(context) {
                cleanupStarted.countDown()
                allowCleanupToFinish.await()
                true
            }
            returned.set(true)
        }

        assertTrue("Cleanup should start", cleanupStarted.await(1, TimeUnit.SECONDS))
        assertFalse("UI gate must not return while cleanup is still running", returned.get())

        allowCleanupToFinish.complete(Unit)
        cleanupThread.join(1_000)

        assertFalse("Cleanup thread should finish after cleanup completes", cleanupThread.isAlive)
        assertTrue("UI gate should return after cleanup completes", returned.get())
    }

    @Test
    fun runBeforeUi_runsCleanupOnlyOncePerProcessReset() {
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
    fun runBeforeUi_retriesAfterCleanupFailure() {
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
