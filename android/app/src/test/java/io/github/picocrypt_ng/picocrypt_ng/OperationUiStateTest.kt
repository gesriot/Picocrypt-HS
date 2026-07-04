package io.github.picocrypt_ng.picocrypt_ng

import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OperationUiStateTest {
    @Test
    fun `cancelled done operation maps to cancelled instead of success`() {
        val state = TestDataBuilders.createOperationState(
            type = OperationType.ENCRYPT,
            status = "Cancelled",
            done = true,
            error = null
        )

        assertEquals(OperationUiState.Cancelled(OperationType.ENCRYPT), state.toUiState())
    }

    @Test
    fun `completed done operation still maps to success`() {
        val state = TestDataBuilders.createOperationState(
            type = OperationType.DECRYPT,
            status = "Completed",
            done = true,
            error = null
        )

        assertEquals(OperationUiState.Success(OperationType.DECRYPT), state.toUiState())
    }

    @Test
    fun `done operation with error still maps to failed even if status says cancelled`() {
        val error = AppError.OperationError.GenericOperation("cancel failed")
        val state = TestDataBuilders.createOperationState(
            type = OperationType.DECRYPT,
            status = "Cancelled",
            done = true,
            error = error
        )

        assertTrue(state.toUiState() is OperationUiState.Failed)
    }
}
