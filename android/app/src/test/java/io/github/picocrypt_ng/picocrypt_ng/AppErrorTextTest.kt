package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppErrorTextTest {
    @Test
    fun `localizedMessage prefers resource text over fallback userMessage`() {
        val context = mockk<Context>()
        every { context.getString(R.string.error_auth_failed) } returns "Localized authentication failure"

        val error = AppError.OperationError.PasswordAuth(
            userMessage = "raw Go auth text",
            technicalMessage = "raw Go auth text",
            messageResId = R.string.error_auth_failed,
        )

        assertEquals("Localized authentication failure", error.localizedMessage(context))
    }

    @Test
    fun `localizedMessage falls back to userMessage when no resource is set`() {
        val error = AppError.OperationError.GenericOperation(
            userMessage = "technical fallback",
            technicalMessage = "technical fallback",
        )

        assertEquals("technical fallback", error.localizedMessage(mockk(relaxed = true)))
    }

    @Test
    fun `generic Go errors keep their raw display message`() {
        val context = mockk<Context>()
        every { context.getString(R.string.error_unknown) } returns "Unknown localized"

        val error = AppError.fromGoError(
            errorString = "header damaged: volume header is damaged",
            operationType = OperationType.DECRYPT,
            code = "CORRUPT_HEADER",
        )

        assertTrue(error is AppError.OperationError.GenericOperation)
        assertEquals(null, error.messageResId)
        assertEquals("header damaged: volume header is damaged", error.localizedMessage(context))
    }

    @Test
    fun `localizedMessage formats validation resource arguments`() {
        val context = mockk<Context>()
        every {
            context.getString(R.string.error_split_volume_not_supported, ".pcv")
        } returns "Move the single .pcv file."

        val error = AppError.ValidationError.SplitVolumeNotSupported

        assertEquals(listOf(".pcv"), error.messageArgs)
        assertEquals("Move the single .pcv file.", error.localizedMessage(context))
    }

    @Test
    fun `AUTH_FAILED maps to password auth with localized display resource`() {
        val error = AppError.fromGoError(
            errorString = "raw auth failure",
            operationType = OperationType.DECRYPT,
            code = "AUTH_FAILED",
        )

        assertTrue(error is AppError.OperationError.PasswordAuth)
        assertTrue(error.allowsPasswordRetry())
        assertFalse(error.allowsForceDecrypt())
        assertEquals(R.string.error_auth_failed, error.messageResId)
        assertEquals("raw auth failure", error.technicalMessage)
    }

    @Test
    fun `DATA_CORRUPTED maps to data corruption with localized display resource`() {
        val error = AppError.fromGoError(
            errorString = "raw integrity failure",
            operationType = OperationType.DECRYPT,
            code = "DATA_CORRUPTED",
        )

        assertTrue(error is AppError.OperationError.DataCorruption)
        assertTrue(error.allowsForceDecrypt())
        assertFalse(error.allowsPasswordRetry())
        assertEquals(R.string.error_data_corrupted, error.messageResId)
        assertEquals("raw integrity failure", error.technicalMessage)
    }
}
