package io.github.picocrypt_ng.picocrypt_ng

import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import org.junit.Assert.assertEquals
import org.junit.Test

class OperationStatusTest {
    @Test
    fun `operation status constants preserve bridge contract strings`() {
        assertEquals("Starting...", OperationStatus.STARTING)
        assertEquals("Completed", OperationStatus.COMPLETED)
        assertEquals("Cancelled", OperationStatus.CANCELLED)
        assertEquals("Error", OperationStatus.ERROR)
    }

    @Test
    fun `cancelled done operation maps to cancelled through status constant`() {
        val state = TestDataBuilders.createOperationState(
            type = OperationType.ENCRYPT,
            status = OperationStatus.CANCELLED,
            done = true,
            error = null,
        )

        assertEquals(OperationUiState.Cancelled(OperationType.ENCRYPT), state.toUiState())
    }
}
