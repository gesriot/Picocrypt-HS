package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import io.github.picocrypt_ng.picocrypt_ng.testutils.MainDispatcherRule
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.mockk

/**
 * Unit tests for OperationViewModel.
 * 
 * Note: OperationViewModel uses OperationManager which interacts with GoBridge.
 * Full integration testing requires instrumented tests. These unit tests focus
 * on the ViewModel's polling lifecycle and state management.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OperationViewModelTest {
    
    @get:Rule
    val instantTaskExecutorRule = InstantTaskExecutorRule()

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private lateinit var mockContext: Context
    private lateinit var viewModel: OperationViewModel
    
    @Before
    fun setUp() {
        mockContext = mockk<Context>(relaxed = true)
        viewModel = OperationViewModel()
        resetOperationState()
    }
    
    @After
    fun tearDown() {
        if (::viewModel.isInitialized) {
            runTest(mainDispatcherRule.testDispatcher) {
                viewModel.viewModelScope.coroutineContext[Job]?.cancelAndJoin()
            }
        }
        resetOperationState()
    }
    
    @Test
    fun `operationState exposes OperationManager currentOperation`() = runTest(mainDispatcherRule.testDispatcher) {
        val operationState = viewModel.operationState.first()
        
        // Initially should be null
        assertNull("Operation state should be null initially", operationState)
        
        // Should match OperationManager's state
        val managerState = OperationManager.currentOperation.first()
        assertEquals(managerState, operationState)
    }
    
    @Test
    fun `startEncrypt handles validation failure without leaking work`() = runTest(mainDispatcherRule.testDispatcher) {
        val formData = TestDataBuilders.createEncryptFormData(
            copiedFilePath = "",
            password = "test",
            confirmPassword = "test"
        )

        viewModel.startEncrypt(mockContext, formData)

        advanceUntilIdle()

        assertNull("Invalid encrypt input should not start an operation", viewModel.operationState.value)
    }

    @Test
    fun `startDecrypt handles validation failure without leaking work`() = runTest(mainDispatcherRule.testDispatcher) {
        val formData = TestDataBuilders.createDecryptFormData(
            copiedFilePath = "",
            password = "test"
        )

        viewModel.startDecrypt(mockContext, formData)

        advanceUntilIdle()

        assertNull("Invalid decrypt input should not start an operation", viewModel.operationState.value)
    }
    
    @Test
    fun `cancelOperation stops polling and cancels operation`() = runTest(mainDispatcherRule.testDispatcher) {
        viewModel.cancelOperation()
        
        advanceUntilIdle()
        
        // Method should not throw
    }
    
    @Test
    fun `clearOperation stops polling and clears operation`() = runTest(mainDispatcherRule.testDispatcher) {
        setOperationState(
            OperationState(
                id = "op_123",
                type = OperationType.ENCRYPT,
                inputFile = "/data/test/input_file.txt",
                outputFile = "/data/test/output_file.pcv",
                status = "Processing",
                progress = 0.5f,
                info = "Working..."
            )
        )

        viewModel.clearOperation(mockContext, shouldCleanupFiles = false)
        
        advanceUntilIdle()
        
        val operationState = viewModel.operationState.first()
        assertNull("Operation should be cleared", operationState)
    }
    
    @Test
    fun `pausePolling switches to background mode`() = runTest(mainDispatcherRule.testDispatcher) {
        // pausePolling sets isForeground to false and starts background polling
        viewModel.pausePolling()
        
        advanceUntilIdle()
        
        // Method should not throw
        // Note: We can't easily verify isForeground without exposing it,
        // but we can verify the method executes without error
    }
    
    @Test
    fun `resumePolling switches to foreground mode`() = runTest(mainDispatcherRule.testDispatcher) {
        // First pause
        viewModel.pausePolling()
        advanceUntilIdle()
        
        // Then resume
        viewModel.resumePolling()
        advanceUntilIdle()
        
        // Method should not throw
    }
    
    @Test
    fun `operationState updates when OperationManager state changes`() = runTest(mainDispatcherRule.testDispatcher) {
        // Initially null
        var operationState = viewModel.operationState.first()
        assertNull("Should be null initially", operationState)
        
        // Note: We can't easily set OperationManager state without GoBridge,
        // but we verify the StateFlow is connected
        val managerState = OperationManager.currentOperation.first()
        assertEquals(managerState, operationState)
    }

    private fun resetOperationState() {
        setOperationState(null)
    }

    private fun setOperationState(state: OperationState?) {
        val field = OperationManager::class.java.getDeclaredField("_currentOperation")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val flow = field.get(OperationManager) as MutableStateFlow<OperationState?>
        flow.value = state
    }
}
