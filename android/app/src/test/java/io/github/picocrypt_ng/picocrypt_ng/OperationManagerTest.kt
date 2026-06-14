package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.mockk
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import io.mockk.slot
import kotlin.io.path.createTempDirectory

/**
 * Unit tests for OperationManager.
 * 
 * Note: OperationManager uses GoBridge and FileCopyService which are objects.
 * Full integration testing requires instrumented tests. These unit tests focus
 * on validation logic and state management that can be tested without full integration.
 */
class OperationManagerTest {
    
    private lateinit var mockContext: Context
    
    @Before
    fun setUp() = runTest {
        mockContext = mockk<Context>(relaxed = true)
        // Clear any existing operation state
        OperationManager.clearOperation(shouldCleanupFiles = false)
    }
    
    @After
    fun tearDown() = runTest {
        // Clean up operation state after each test
        OperationManager.clearOperation(shouldCleanupFiles = false)
    }
    
    @Test
    fun `startEncrypt returns error when no file selected`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            copiedFilePath = "" // Empty file path
        )
        
        val result = OperationManager.startEncrypt(mockContext, formData)
        
        assertTrue("Should fail with NoFileSelected", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be NoFileSelected", error is AppError.ValidationError.NoFileSelected)
        }
    }
    
    @Test
    fun `startEncrypt returns error when password invalid`() = runTest {
        val formData = FormData(
            selectedFilename = "test.txt",
            copiedFilePath = "/path/to/file.txt",
            passwordInput = CharArray(0), // Empty password
            confirmPasswordInput = CharArray(0),
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        
        val result = OperationManager.startEncrypt(mockContext, formData)
        
        assertTrue("Should fail with InvalidPassword", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be InvalidPassword", error is AppError.ValidationError.InvalidPassword)
        }
    }
    
    @Test
    fun `startEncrypt returns error when passwords do not match`() = runTest {
        val formData = FormData(
            selectedFilename = "test.txt",
            copiedFilePath = "/path/to/file.txt",
            passwordInput = "password1".toCharArray(),
            confirmPasswordInput = "password2".toCharArray(), // Mismatch
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        
        val result = OperationManager.startEncrypt(mockContext, formData)
        
        assertTrue("Should fail with PasswordsMismatch", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be PasswordsMismatch", error is AppError.ValidationError.PasswordsMismatch)
        }
    }
    
    @Test
    fun `startDecrypt returns error when no file selected`() = runTest {
        val formData = TestDataBuilders.createDecryptFormData(
            copiedFilePath = "" // Empty file path
        )
        
        val result = OperationManager.startDecrypt(mockContext, formData)
        
        assertTrue("Should fail with NoFileSelected", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be NoFileSelected", error is AppError.ValidationError.NoFileSelected)
        }
    }
    
    @Test
    fun `startDecrypt returns error when password invalid`() = runTest {
        val formData = FormData(
            selectedFilename = "test.pcv",
            copiedFilePath = "/path/to/file.pcv",
            passwordInput = CharArray(0), // Empty password
            confirmPasswordInput = CharArray(0),
            comments = "",
            reedSolomon = false,
            paranoid = false,
            deniability = false,
            keyfileFilenames = emptyList(),
            keyfileOrdered = false
        )
        
        val result = OperationManager.startDecrypt(mockContext, formData)
        
        assertTrue("Should fail with InvalidPassword", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be InvalidPassword", error is AppError.ValidationError.InvalidPassword)
        }
    }
    
    @Test
    fun `cancelOperation returns error when no active operation`() = runTest {
        // Ensure no operation is active
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.cancelOperation()
        
        assertTrue("Should fail with no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
            val errorMessage = error.message ?: ""
            assertTrue("Error message should mention no active operation", 
                errorMessage.contains("No active operation", ignoreCase = true))
        }
    }
    
    @Test
    fun `pollProgress returns null when no active operation`() = runTest {
        // Ensure no operation is active
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.pollProgress()
        
        assertNull("Should return null when no operation", result)
    }
    
    @Test
    fun `pollProgress does not overwrite a terminal (done) state with a stale poll`() = runTest {
        // GoBridge is an object backed by the Go mobile AAR, which is absent on the JVM
        // unit-test classpath. Mock it so we can (a) drive _currentOperation to a real
        // done=true state via the only public seam (startEncrypt + pollProgress), then
        // (b) prove the done-guard rejects a later stale poll. This is the narrowest
        // reachable level: there is no public setter for _currentOperation.
        // startEncrypt resolves an output path under context.filesDir; the relaxed mock
        // returns null for it, so back it with a real temp dir.
        val tmpDir = createTempDirectory(prefix = "opmgr_test").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_test")
            every {
                GoBridge.startEncrypt(any(), any(), any(), any(), any(), any(), any(), any())
            } returns Result.success(Unit)

            // Establish an active (non-done) operation.
            val started = OperationManager.startEncrypt(
                mockContext,
                TestDataBuilders.createEncryptFormData()
            )
            assertTrue("startEncrypt should succeed", started.isSuccess)

            // First poll transitions the operation to a terminal done=true state.
            every { GoBridge.getProgress("op_test") } returns Result.success(
                ProgressState(status = "Completed", progress = 1f, info = "", done = true)
            )
            val terminal = OperationManager.pollProgress()
            assertNotNull("Poll should return the terminal state", terminal)
            assertTrue("State should be done after terminal poll", terminal!!.done)

            // A later (slow/concurrent) poll reports a stale, non-terminal progress.
            every { GoBridge.getProgress("op_test") } returns Result.success(
                ProgressState(status = "Working...", progress = 0.42f, info = "stale", done = false)
            )
            val afterStale = OperationManager.pollProgress()

            // The done-guard must keep the terminal state intact, not regress it.
            assertNotNull(afterStale)
            assertTrue("Done flag must remain true", afterStale!!.done)
            assertEquals("Status must not regress", "Completed", afterStale.status)
            assertEquals("Progress must not regress", 1f, afterStale.progress, 0.001f)
            assertSame(
                "Terminal state must be returned unchanged",
                terminal,
                afterStale
            )
            assertSame(
                "currentOperation must still hold the terminal state",
                terminal,
                OperationManager.currentOperation.value
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `pollProgress does not resurrect a concurrently-cleared operation`() = runTest {
        // RACE: the FGS (1000ms) and the ViewModel (500ms) both poll concurrently.
        // pollProgress is a read-modify-write: it captures _currentOperation, then
        // suspends in GoBridge.getProgress (I/O). If another coroutine calls
        // clearOperation() during that window (_currentOperation -> null), an
        // UNCONDITIONAL write of the captured op would RESURRECT the cleared op as a
        // phantom non-done state. The write must no-op instead.
        //
        // Deterministic, not timing-based: model the concurrent clear as a SIDE EFFECT
        // of the getProgress stub -- it nulls _currentOperation (exactly what
        // clearOperation does to the flow; done directly because clearOperation is a
        // suspend fun and the MockK answers block is not a coroutine body), THEN
        // returns a non-done progress. After pollProgress, _currentOperation must
        // still be null. GoBridge is the Go mobile AAR (absent on the JVM classpath),
        // so mock it. startEncrypt resolves an output path under context.filesDir;
        // back it with a real temp dir since the relaxed mock returns null.
        val tmpDir = createTempDirectory(prefix = "opmgr_resurrect_test").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_clear")
            every {
                GoBridge.startEncrypt(any(), any(), any(), any(), any(), any(), any(), any())
            } returns Result.success(Unit)

            // Establish an active (non-done) operation through the public seam.
            val started = OperationManager.startEncrypt(
                mockContext,
                TestDataBuilders.createEncryptFormData()
            )
            assertTrue("startEncrypt should succeed", started.isSuccess)
            assertNotNull("operation should be active", OperationManager.currentOperation.value)

            val stateField = OperationManager::class.java.getDeclaredField("_currentOperation")
            stateField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val flow = stateField.get(OperationManager)
                as kotlinx.coroutines.flow.MutableStateFlow<OperationState?>

            // getProgress simulates a concurrent clear during its I/O, then returns a
            // live, non-terminal progress for the now-stale captured operation.
            every { GoBridge.getProgress("op_clear") } answers {
                flow.value = null
                Result.success(
                    ProgressState(status = "Encrypting", progress = 0.5f, info = "", done = false)
                )
            }

            val result = OperationManager.pollProgress()

            assertNull("Cleared operation must not be resurrected (return)", result)
            assertNull(
                "Cleared operation must not be resurrected (currentOperation)",
                OperationManager.currentOperation.value
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `pollProgress does not clobber a replaced operation`() = runTest {
        // Same race window, different concurrent action: instead of clearing,
        // another coroutine REPLACES _currentOperation with a different-id op (e.g. a
        // new operation started while a slow poll was in flight). The unconditional
        // write of the captured op would clobber the newer op; the id-guard must
        // leave the replacement untouched.
        val tmpDir = createTempDirectory(prefix = "opmgr_clobber_test").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_old")
            every {
                GoBridge.startEncrypt(any(), any(), any(), any(), any(), any(), any(), any())
            } returns Result.success(Unit)

            val started = OperationManager.startEncrypt(
                mockContext,
                TestDataBuilders.createEncryptFormData()
            )
            assertTrue("startEncrypt should succeed", started.isSuccess)

            // A different-id operation installed concurrently during getProgress I/O.
            val replacement = TestDataBuilders.createOperationState(
                id = "op_new",
                type = OperationType.ENCRYPT,
                status = "Starting...",
                progress = 0f,
                done = false
            )
            val stateField = OperationManager::class.java.getDeclaredField("_currentOperation")
            stateField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val flow = stateField.get(OperationManager)
                as kotlinx.coroutines.flow.MutableStateFlow<OperationState?>

            every { GoBridge.getProgress("op_old") } answers {
                flow.value = replacement
                Result.success(
                    ProgressState(status = "Encrypting", progress = 0.5f, info = "", done = false)
                )
            }

            val result = OperationManager.pollProgress()

            assertSame("Replacement op must be returned unchanged", replacement, result)
            assertSame(
                "currentOperation must still hold the replacement op",
                replacement,
                OperationManager.currentOperation.value
            )
            assertEquals("Replacement id must be intact", "op_new", result!!.id)
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `clearOperation clears current operation`() = runTest {
        // First, we'd need to set up an operation, but since we can't easily mock GoBridge,
        // we'll test that clearOperation works when called
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val currentOp = OperationManager.currentOperation.first()
        assertNull("Operation should be null after clearing", currentOp)
    }
    
    @Test
    fun `clearOperation clears passwords from form data`() = runTest {
        val formData = TestDataBuilders.createEncryptFormData(
            password = "testpassword",
            confirmPassword = "testpassword"
        )
        
        // Create a mock operation state
        val operationState = TestDataBuilders.createOperationState(
            formData = formData
        )
        
        // We can't directly set the operation state, but we can test the password clearing
        // by checking that clearPasswords works
        val passwordBefore = formData.passwordInput.copyOf()
        formData.clearPasswords()
        
        assertTrue("Password should be cleared", formData.passwordInput.all { it == '\u0000' })
        assertTrue("Confirm password should be cleared", formData.confirmPasswordInput.all { it == '\u0000' })
    }
    
    @Test
    fun `retryOperation returns error when no active operation`() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val formData = TestDataBuilders.createEncryptFormData()
        val result = OperationManager.retryOperation(mockContext, formData)
        
        assertTrue("Should fail with no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
            val errorMessage = error.message ?: ""
            assertTrue("Error message should mention no active operation to retry",
                errorMessage.contains("No active operation to retry", ignoreCase = true))
        }
    }
    
    @Test
    fun `retryOperation returns error when form data invalid`() = runTest {
        // We can't easily set up an operation without GoBridge, but we can test
        // that retryOperation validates form data
        val invalidFormData = TestDataBuilders.createEncryptFormData(
            copiedFilePath = "" // Invalid - no file
        )
        
        // This will fail because there's no active operation, but we're testing
        // the validation logic that happens after checking for active operation
        val result = OperationManager.retryOperation(mockContext, invalidFormData)
        
        // Will fail either because no active operation or invalid form data
        assertTrue("Should fail", result.isFailure)
    }
    
    @Test
    fun `retryDecryptWithForce returns error when no active operation`() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val result = OperationManager.retryDecryptWithForce()
        
        assertTrue("Should fail with no active operation", result.isFailure)
        result.onFailure { error ->
            assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        }
    }
    
    @Test
    fun `retryDecryptWithForce fails loud when stored formData has an empty password`() = runTest {
        // Force-decrypt BYPASSES integrity/RS checks, so running it with an empty
        // password (a CharArray(0) the form layer installs on clear -- see
        // MainViewModel.clearSensitiveData / resetFormToDefaults) would silently run
        // and produce garbage. Reproduce that exact state: a DECRYPT operation whose
        // stored formData carries CharArray(0). startDecrypt validates the password,
        // so it can't seed an empty-password operation directly; establish it with a
        // valid password through the public seam, then swap in the empty-password
        // formData via the private _currentOperation MutableStateFlow (white-box;
        // there is no public setter). GoBridge is the Go mobile AAR (absent on the JVM
        // classpath), so mock it -- the guard must short-circuit BEFORE
        // GoBridge.startOperation/startDecrypt are reached on the retry.
        val tmpDir = createTempDirectory(prefix = "opmgr_force_test").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_force")
            every { GoBridge.startDecrypt(any(), any(), any(), any(), any()) } returns Result.success(Unit)

            // Establish an active DECRYPT operation with a valid password.
            val started = OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData()
            )
            assertTrue("startDecrypt should succeed", started.isSuccess)

            // Swap the stored formData for one with an empty password (CharArray(0)),
            // mirroring a post-clear form state, keeping the DECRYPT operation.
            val established = OperationManager.currentOperation.value
            assertNotNull("operation should be established", established)
            val emptyPwForm = established!!.formData!!.copy(
                passwordInput = CharArray(0),
                confirmPasswordInput = CharArray(0)
            )
            assertFalse("seeded formData must be invalid", emptyPwForm.isPasswordValid)
            val stateField = OperationManager::class.java.getDeclaredField("_currentOperation")
            stateField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val flow = stateField.get(OperationManager)
                as kotlinx.coroutines.flow.MutableStateFlow<OperationState?>
            flow.value = established.copy(formData = emptyPwForm)

            val result = OperationManager.retryDecryptWithForce()

            assertTrue("Force-decrypt with an empty password must fail loud", result.isFailure)
            result.onFailure { error ->
                assertTrue(
                    "Error should be InvalidPassword",
                    error is AppError.ValidationError.InvalidPassword
                )
            }

            // The guard must short-circuit before touching the Go bridge on the retry:
            // exactly one startOperation + one startDecrypt, both from the setup call.
            verify(exactly = 1) { GoBridge.startOperation() }
            verify(exactly = 1) { GoBridge.startDecrypt(any(), any(), any(), any(), any()) }
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `retryDecryptWithForce returns error when operation is not decrypt`() = runTest {
        // The guard at OperationManager.retryDecryptWithForce rejects a non-DECRYPT
        // operation (operation.type != DECRYPT -> GenericOperation("Can only retry
        // decryption operations")). It short-circuits BEFORE any decrypt-side GoBridge
        // call, so the Go AAR is not needed — establish an ENCRYPT op through the public
        // seam (GoBridge mocked) and assert the rejection. startEncrypt resolves an
        // output path under context.filesDir; back it with a real temp dir.
        val tmpDir = createTempDirectory(prefix = "opmgr_notdecrypt").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_enc")
            every {
                GoBridge.startEncrypt(any(), any(), any(), any(), any(), any(), any(), any())
            } returns Result.success(Unit)

            val started = OperationManager.startEncrypt(
                mockContext,
                TestDataBuilders.createEncryptFormData()
            )
            assertTrue("startEncrypt should succeed", started.isSuccess)
            assertEquals(OperationType.ENCRYPT, OperationManager.currentOperation.value?.type)

            val result = OperationManager.retryDecryptWithForce()

            assertTrue("Force-decrypt retry on an encrypt op must fail", result.isFailure)
            result.onFailure { error ->
                assertTrue(
                    "Error should be GenericOperation",
                    error is AppError.OperationError.GenericOperation
                )
                assertTrue(
                    "Message should explain only decryption can be retried",
                    (error.message ?: "").contains("Can only retry decryption", ignoreCase = true)
                )
            }
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }
    
    @Test
    fun `currentOperation StateFlow is initially null`() = runTest {
        OperationManager.clearOperation(shouldCleanupFiles = false)
        
        val currentOp = OperationManager.currentOperation.first()
        assertNull("Current operation should be null initially", currentOp)
    }
    
    @Test
    fun `OperationState has correct structure`() {
        val formData = TestDataBuilders.createEncryptFormData()
        val operationState = TestDataBuilders.createOperationState(
            id = "op_123",
            type = OperationType.ENCRYPT,
            inputFile = "/input.txt",
            outputFile = "/output.pcv",
            status = "Processing",
            progress = 0.5f,
            info = "Encrypting...",
            done = false,
            formData = formData
        )
        
        assertEquals("op_123", operationState.id)
        assertEquals(OperationType.ENCRYPT, operationState.type)
        assertEquals("/input.txt", operationState.inputFile)
        assertEquals("/output.pcv", operationState.outputFile)
        assertEquals("Processing", operationState.status)
        assertEquals(0.5f, operationState.progress, 0.001f)
        assertEquals("Encrypting...", operationState.info)
        assertEquals(false, operationState.done)
        assertEquals(formData, operationState.formData)
    }
    
    @Test
    fun `OperationType enum values are correct`() {
        assertEquals("ENCRYPT", OperationType.ENCRYPT.name)
        assertEquals("DECRYPT", OperationType.DECRYPT.name)
    }

    @Test
    fun `startDecrypt passes verifyFirst from formData into DecryptOptions`() = runTest {
        // verifyFirst is a security option (integrity-verify-before-write). It is wired
        // through the Go bridge (GoBridge.DecryptOptions.verifyFirst -> android.go) but
        // OperationManager historically hardcoded it false. Capture the DecryptOptions
        // handed to GoBridge.startDecrypt and prove the form value flows through.
        // GoBridge is the Go mobile AAR (absent on the JVM classpath), so mock it;
        // startDecrypt resolves an output path under context.filesDir, so back it with
        // a real temp dir (the relaxed mock returns null otherwise).
        val tmpDir = createTempDirectory(prefix = "opmgr_verifyfirst").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_vf")
            val optionsSlot = slot<DecryptOptions>()
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), capture(optionsSlot))
            } returns Result.success(Unit)

            val formData = TestDataBuilders.createDecryptFormData().copy(verifyFirst = true)
            val result = OperationManager.startDecrypt(mockContext, formData)

            assertTrue("startDecrypt should succeed", result.isSuccess)
            assertTrue("DecryptOptions must be captured", optionsSlot.isCaptured)
            assertTrue(
                "verifyFirst must flow from formData into the Go bridge call",
                optionsSlot.captured.verifyFirst
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `startDecrypt does not auto-unzip so zip volumes stay exportable`() = runTest {
        // INTEROP (core value): a desktop volume made from multiple files / compression
        // decrypts to a .zip. Go's auto-unzip extracts to a SUBDIRECTORY and DELETES the
        // zip (decrypt.go:816,847); Android then exports a single fixed output path, so
        // the export reads a now-missing/directory path -> SaveFailed. Until a SAF
        // tree-export exists, Android must NOT auto-unzip: the intact .zip stays the one
        // exportable output (matches the CLI --auto-unzip default of false, decrypt.go:94).
        // Capture the DecryptOptions handed to the Go bridge and prove autoUnzip is off.
        val tmpDir = createTempDirectory(prefix = "opmgr_autounzip").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_unzip")
            val optionsSlot = slot<DecryptOptions>()
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), capture(optionsSlot))
            } returns Result.success(Unit)

            val result = OperationManager.startDecrypt(
                mockContext,
                TestDataBuilders.createDecryptFormData()
            )

            assertTrue("startDecrypt should succeed", result.isSuccess)
            assertTrue("DecryptOptions must be captured", optionsSlot.isCaptured)
            assertFalse(
                "auto-unzip must be OFF on Android (no SAF tree-export; the zip volume must stay exportable)",
                optionsSlot.captured.autoUnzip
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `retryDecryptWithForce does not auto-unzip`() = runTest {
        // Same interop invariant as startDecrypt, on the force-decrypt retry path
        // (retryDecryptWithForce builds its own DecryptOptions). The slot captures the
        // last GoBridge.startDecrypt call -- the retry -- which must set forceDecrypt
        // (proving it is the retry) and keep autoUnzip off.
        val tmpDir = createTempDirectory(prefix = "opmgr_autounzip_force").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_unzip_force")
            val optionsSlot = slot<DecryptOptions>()
            every {
                GoBridge.startDecrypt(any(), any(), any(), any(), capture(optionsSlot))
            } returns Result.success(Unit)

            assertTrue(
                "startDecrypt setup should succeed",
                OperationManager.startDecrypt(
                    mockContext,
                    TestDataBuilders.createDecryptFormData()
                ).isSuccess
            )
            val retry = OperationManager.retryDecryptWithForce()

            assertTrue("retryDecryptWithForce should succeed", retry.isSuccess)
            assertTrue("DecryptOptions must be captured", optionsSlot.isCaptured)
            assertTrue("retry path must set forceDecrypt", optionsSlot.captured.forceDecrypt)
            assertFalse(
                "auto-unzip must be OFF on the force-retry path too",
                optionsSlot.captured.autoUnzip
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `startEncrypt on a folder selection sends empty inputFile and the staged arrays`() = runTest {
        // A folder/multi selection encrypts the staged tree, not a single copied file.
        // OperationManager must hand GoBridge an EMPTY inputFile (so Go does not also try
        // to read a non-existent single path) and forward the inputFiles/onlyFolders the
        // staging step produced. Capture the bridge args and prove the selection flows
        // through. GoBridge is the Go mobile AAR (absent on the JVM classpath), so mock
        // it; startEncrypt resolves an output path under context.filesDir, so back it
        // with a real temp dir (the relaxed mock returns null otherwise).
        val tmpDir = createTempDirectory(prefix = "opmgr_folder").toFile()
        every { mockContext.filesDir } returns tmpDir

        mockkObject(GoBridge)
        try {
            every { GoBridge.startOperation() } returns Result.success("op_folder")
            val inputFileSlot = slot<String>()
            val inputFilesSlot = slot<List<String>>()
            val onlyFoldersSlot = slot<List<String>>()
            every {
                GoBridge.startEncrypt(
                    any(),
                    capture(inputFileSlot),
                    any(),
                    any(),
                    any(),
                    inputFiles = capture(inputFilesSlot),
                    onlyFolders = capture(onlyFoldersSlot),
                    onlyFiles = any(),
                )
            } returns Result.success(Unit)

            val formData = TestDataBuilders.createFolderEncryptFormData(displayName = "MyDocs")
            val result = OperationManager.startEncrypt(mockContext, formData)

            assertTrue("folder encrypt should start", result.isSuccess)
            assertTrue("bridge args must be captured", inputFilesSlot.isCaptured)
            assertEquals(
                "a multi selection must send an empty single inputFile",
                "",
                inputFileSlot.captured
            )
            assertEquals(
                "the staged inputFiles must flow to the bridge",
                formData.inputFiles,
                inputFilesSlot.captured
            )
            assertEquals(
                "the staged onlyFolders must flow to the bridge",
                formData.onlyFolders,
                onlyFoldersSlot.captured
            )
        } finally {
            unmockkObject(GoBridge)
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun `startEncrypt fails loud on a folder selection with no staged files`() = runTest {
        // A FOLDER selectionKind with an empty inputFiles list is an invalid selection
        // (staging produced nothing). It must fail with NoFileSelected before any Go work,
        // exactly as an empty single-file copiedFilePath does.
        mockkObject(GoBridge)
        try {
            val formData = TestDataBuilders.createFolderEncryptFormData()
                .copy(inputFiles = emptyList())
            val result = OperationManager.startEncrypt(mockContext, formData)

            assertTrue("empty folder selection must fail", result.isFailure)
            result.onFailure {
                assertTrue(
                    "Error should be NoFileSelected",
                    it is AppError.ValidationError.NoFileSelected
                )
            }
            verify(exactly = 0) { GoBridge.startOperation() }
        } finally {
            unmockkObject(GoBridge)
        }
    }

    @Test
    fun `startEncrypt fails loud on a split-volume chunk`() = runTest {
        // A .pcv.N chunk does NOT end in .pcv, so FormData.isEncrypt is true -- the work
        // button would DOUBLE-ENCRYPT it. Android cannot recombine (single-file picker),
        // so the operation must fail loud BEFORE reaching the Go bridge.
        mockkObject(GoBridge)
        try {
            val formData = TestDataBuilders.createEncryptFormData(
                selectedFilename = "secret.pcv.0",
                copiedFilePath = "/data/test/input_file"
            )
            val result = OperationManager.startEncrypt(mockContext, formData)

            assertTrue("Split chunk must fail", result.isFailure)
            result.onFailure {
                assertTrue(
                    "Error should be SplitVolumeNotSupported",
                    it is AppError.ValidationError.SplitVolumeNotSupported
                )
            }
            // Must short-circuit before any Go work.
            verify(exactly = 0) { GoBridge.startOperation() }
        } finally {
            unmockkObject(GoBridge)
        }
    }

    @Test
    fun `startDecrypt fails loud on a split-volume chunk`() = runTest {
        // A desktop split volume selected on Android (secret.pcv.0) cannot be decrypted
        // without recombining its sibling chunks, which Android has no way to supply.
        // Fail loud instead of running the Go op on one chunk (confusing corrupt error).
        mockkObject(GoBridge)
        try {
            val formData = TestDataBuilders.createDecryptFormData(
                selectedFilename = "secret.pcv.0",
                copiedFilePath = "/data/test/input_file"
            )
            val result = OperationManager.startDecrypt(mockContext, formData)

            assertTrue("Split chunk must fail", result.isFailure)
            result.onFailure {
                assertTrue(
                    "Error should be SplitVolumeNotSupported",
                    it is AppError.ValidationError.SplitVolumeNotSupported
                )
            }
            verify(exactly = 0) { GoBridge.startOperation() }
        } finally {
            unmockkObject(GoBridge)
        }
    }
}

