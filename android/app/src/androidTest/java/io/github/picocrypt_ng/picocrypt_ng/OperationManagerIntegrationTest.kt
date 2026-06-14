package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
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
 * Integration tests for OperationManager.
 * These tests require the Go mobile bindings AAR to be built and test
 * the full operation lifecycle with real file operations.
 * 
 * Note: Some tests may be skipped if Go mobile bindings are not available.
 */
@RunWith(AndroidJUnit4::class)
class OperationManagerIntegrationTest {
    
    private lateinit var context: Context

    private fun encryptFormData(
        copiedFilePath: String = "/data/test/input_file.txt",
        password: String = "testpassword",
        confirmPassword: String = password,
        keyfiles: List<KeyfileInfo> = emptyList()
    ) = FormData(
        selectedFilename = "test.txt",
        copiedFilePath = copiedFilePath,
        comments = "",
        passwordInput = password.toCharArray(),
        confirmPasswordInput = confirmPassword.toCharArray(),
        reedSolomon = false,
        paranoid = false,
        deniability = false,
        keyfileFilenames = keyfiles,
        keyfileOrdered = false,
        decryptionInfo = null
    )

    private fun decryptFormData(
        copiedFilePath: String = "/data/test/input_file.pcv",
        password: String = "testpassword"
    ) = FormData(
        selectedFilename = "test.pcv",
        copiedFilePath = copiedFilePath,
        comments = "",
        passwordInput = password.toCharArray(),
        confirmPasswordInput = password.toCharArray(),
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
    fun startEncrypt_validates_form_data_before_starting() = runTest {
        // Test with invalid form data (no file)
        val invalidFormData = encryptFormData(
            copiedFilePath = "" // Invalid - no file
        )
        
        val result = OperationManager.startEncrypt(context, invalidFormData)
        
        assertTrue("Should fail validation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be NoFileSelected", error is AppError.ValidationError.NoFileSelected)
        }
        
        // Verify no operation was started
        val operationState = OperationManager.currentOperation.first()
        assertNull("No operation should be started", operationState)
    }
    
    @Test
    fun startDecrypt_validates_form_data_before_starting() = runTest {
        // Test with invalid form data (no file)
        val invalidFormData = decryptFormData(
            copiedFilePath = "" // Invalid - no file
        )
        
        val result = OperationManager.startDecrypt(context, invalidFormData)
        
        assertTrue("Should fail validation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be NoFileSelected", error is AppError.ValidationError.NoFileSelected)
        }
        
        // Verify no operation was started
        val operationState = OperationManager.currentOperation.first()
        assertNull("No operation should be started", operationState)
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
    
    @Test
    fun pollProgress_returns_null_without_active_operation() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)

        val result = OperationManager.pollProgress()

        assertNull("pollProgress should return null when no operation is active", result)
    }
    
    @Test
    fun cancelOperation_updates_operation_state_to_cancelled() = runTest {
        // This test requires an active operation
        // We'll test the error case when no operation exists
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.cancelOperation()
        
        assertTrue("Should fail when no operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        }
    }
    
    @Test
    fun clearOperation_removes_operation_state() = runTest {
        OperationManager.clearOperation(context, shouldCleanupFiles = false)
        
        val operationState = OperationManager.currentOperation.first()
        assertNull("Operation should be cleared", operationState)
    }
    
    @Test
    fun clearOperation_cleans_up_files_when_requested() = runTest {
        // Create test files
        val internalDir = File(context.filesDir, "picocrypt_files")
        internalDir.mkdirs()
        val inputFile = File(internalDir, "input_file.txt")
        val outputFile = File(internalDir, "output_file.pcv")
        val keyfile = File(internalDir, "keyfile_0")
        inputFile.writeText("input")
        outputFile.writeText("output")
        keyfile.writeText("keyfile")
        
        // Create a mock operation state by manually setting up files
        // (We can't easily create a real operation without Go mobile bindings)
        // But we can test that clearOperation cleans up files
        
        val formData = encryptFormData(
            copiedFilePath = inputFile.absolutePath,
            keyfiles = listOf(KeyfileInfo(internalPath = keyfile.absolutePath, displayName = keyfile.name))
        )
        
        // Note: We can't set operation state directly, but we can test
        // that FileCopyService.cleanupOperationFiles works
        FileCopyService.cleanupOperationFiles(
            context = context,
            inputFilePath = inputFile.absolutePath,
            outputFilePath = outputFile.absolutePath,
            keyfilePaths = listOf(keyfile.absolutePath)
        )
        
        assertFalse("Input file should be deleted", inputFile.exists())
        assertFalse("Output file should be deleted", outputFile.exists())
        assertFalse("Keyfile should be deleted", keyfile.exists())
    }
    
    @Test
    fun retryOperation_requires_active_operation() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val formData = encryptFormData(
            password = "test",
            confirmPassword = "test"
        )
        
        val result = OperationManager.retryOperation(context, formData)
        
        assertTrue("Should fail when no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        }
    }
    
    @Test
    fun retryDecryptWithForce_requires_active_decrypt_operation() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.retryDecryptWithForce()
        
        assertTrue("Should fail when no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        }
    }
    
    @Test
    fun currentOperation_stateFlow_reflects_operation_state() = runTest {
        // Initially should be null
        var operationState = OperationManager.currentOperation.first()
        assertNull("Should be null initially", operationState)
        
        // After clearing, should still be null
        OperationManager.clearOperation(shouldCleanupFiles = false)
        operationState = OperationManager.currentOperation.first()
        assertNull("Should be null after clearing", operationState)
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
