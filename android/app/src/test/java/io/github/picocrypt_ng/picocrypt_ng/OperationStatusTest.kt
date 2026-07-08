package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import io.mockk.every
import io.mockk.mockk
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
    fun `operation status constants localize for display while preserving bridge constants`() {
        val context = mockk<Context>()
        every { context.getString(R.string.status_starting) } returns "Localized starting"
        every { context.getString(R.string.status_completed) } returns "Localized completed"
        every { context.getString(R.string.status_cancelled) } returns "Localized cancelled"
        every { context.getString(R.string.status_error) } returns "Localized error"
        every { context.getString(R.string.unknown) } returns "Localized unknown"

        assertEquals("Localized starting", localizedOperationStatus(context, OperationStatus.STARTING))
        assertEquals("Localized completed", localizedOperationStatus(context, OperationStatus.COMPLETED))
        assertEquals("Localized cancelled", localizedOperationStatus(context, OperationStatus.CANCELLED))
        assertEquals("Localized error", localizedOperationStatus(context, OperationStatus.ERROR))
        assertEquals("Custom status", localizedOperationStatus(context, "Custom status"))
        assertEquals("Localized unknown", localizedOperationStatus(context, ""))
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
