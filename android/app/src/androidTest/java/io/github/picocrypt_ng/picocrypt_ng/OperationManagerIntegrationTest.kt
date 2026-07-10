package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * On-device integration coverage for the Kotlin -> gomobile/JNI -> Go crypto path.
 * JVM tests cover validation and state-management branches; this class keeps only
 * the behavior that requires a real Android runtime and the native AAR.
 */
@RunWith(AndroidJUnit4::class)
class OperationManagerIntegrationTest {
    
    private lateinit var context: Context

    private fun encryptFormData(
        copiedFilePath: String
    ) = FormData(
        selectedFilename = "test.txt",
        copiedFilePath = copiedFilePath,
        comments = "",
        passwordInput = "testpassword".toCharArray(),
        confirmPasswordInput = "testpassword".toCharArray(),
        reedSolomon = false,
        paranoid = false,
        deniability = false,
        keyfileFilenames = emptyList(),
        keyfileOrdered = false,
        decryptionInfo = null
    )

    private fun decryptFormData(
        copiedFilePath: String
    ) = FormData(
        selectedFilename = "test.pcv",
        copiedFilePath = copiedFilePath,
        comments = "",
        passwordInput = "testpassword".toCharArray(),
        confirmPasswordInput = "testpassword".toCharArray(),
        reedSolomon = false,
        paranoid = false,
        deniability = false,
        keyfileFilenames = emptyList(),
        keyfileOrdered = false,
        decryptionInfo = null
    )
    
    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        // Clean up any existing operations and files
        runTest {
            OperationManager.clearOperation(context, shouldCleanupFiles = true)
            FileCopyService.cleanupAllFiles(context)
        }
    }
    
    @After
    fun tearDown() {
        // Clean up after each test
        runTest {
            OperationManager.clearOperation(context, shouldCleanupFiles = true)
            FileCopyService.cleanupAllFiles(context)
        }
    }
    
    @Test
    fun encrypt_then_decrypt_recovers_the_original_bytes() = runBlocking {
        // The point of an ON-DEVICE gate: prove that real bytes survive
        // encrypt -> gomobile/JNI bridge -> native crypto -> decrypt on an actual device.
        // `go test` already covers the crypto math but never crosses the bridge, so this is
        // the only place that proves the bridge + AAR + KDF/cipher actually round-trip.
        // runBlocking (not runTest) so the wait runs in real wall-clock time.
        val original = (
            "Picocrypt-NG on-device roundtrip — éçü 0123456789 " +
                "the quick brown fox jumps over the lazy dog"
            ).toByteArray(Charsets.UTF_8)
        val internalDir = File(context.filesDir, "picocrypt_files").apply { mkdirs() }
        val plaintext = File(internalDir, "roundtrip_input.txt")
        plaintext.writeBytes(original)

        // Encrypt.
        val encStart = OperationManager.startEncrypt(
            context,
            encryptFormData(copiedFilePath = plaintext.absolutePath)
        )
        assertTrue("encrypt should start: ${encStart.exceptionOrNull()}", encStart.isSuccess)
        val encState = waitForOperationToFinish()
        assertNull("encrypt must not finish with an error", encState.error)
        val encryptedFile = File(encState.outputFile)
        assertTrue("encrypted volume must exist", encryptedFile.exists())
        assertFalse(
            "ciphertext must differ from plaintext (data was actually encrypted)",
            encryptedFile.readBytes().contentEquals(original)
        )
        OperationManager.clearOperation(context, shouldCleanupFiles = false)

        // Re-stage the ciphertext as a decrypt INPUT, mirroring the real app: a picked
        // .pcv is copied to input_file.<ext>. startDecrypt's pre-clean wipes output_file.*
        // (never input_file.*), so feeding the raw encrypt output back in would delete it.
        val decryptInput = File(internalDir, "input_file.pcv")
        encryptedFile.copyTo(decryptInput, overwrite = true)

        // Decrypt the volume we just produced.
        val decStart = OperationManager.startDecrypt(
            context,
            decryptFormData(copiedFilePath = decryptInput.absolutePath)
        )
        assertTrue("decrypt should start: ${decStart.exceptionOrNull()}", decStart.isSuccess)
        val decState = waitForOperationToFinish()
        assertNull("decrypt must not finish with an error", decState.error)
        val decryptedFile = File(decState.outputFile)
        assertTrue("decrypted output must exist", decryptedFile.exists())

        // The assertion that actually matters: the bytes came back intact.
        assertArrayEquals(
            "decrypted bytes must equal the original plaintext",
            original,
            decryptedFile.readBytes()
        )
    }
    
    // Polls the async Go operation to completion in REAL wall-clock time. The gomobile
    // bridge is start-then-poll by design, so polling is unavoidable; the budget is large
    // enough (~60s for an Argon2id KDF that takes seconds) that only a genuine bug -- not a
    // slow emulator -- can trip it. delay() is forced onto a real dispatcher so a
    // virtual-time test scheduler cannot collapse it to zero.
    private suspend fun waitForOperationToFinish(maxPolls: Int = 600): OperationState {
        repeat(maxPolls) {
            val state = OperationManager.pollProgress()
            if (state != null && state.done) {
                return state
            }
            withContext(Dispatchers.IO) { delay(100) }
        }
        throw AssertionError("Timed out waiting for operation to finish")
    }
}
