package io.github.picocrypt_ng.picocrypt_ng

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for AppError class.
 */
class AppErrorTest {
    
    @Test
    fun `isDataCorruption returns true for DataCorruption error`() {
        val error = AppError.OperationError.DataCorruption(
            userMessage = "Data corrupted",
            technicalMessage = "Corruption detected"
        )
        assertTrue(error.isDataCorruption())
        assertTrue(error.allowsForceDecrypt())
    }
    
    @Test
    fun `isDataCorruption returns false for other error types`() {
        val passwordError = AppError.OperationError.PasswordAuth("Wrong password")
        val fileError = AppError.OperationError.FileNotFound()
        val genericError = AppError.OperationError.GenericOperation("Generic error")
        
        assertFalse(passwordError.isDataCorruption())
        assertFalse(fileError.isDataCorruption())
        assertFalse(genericError.isDataCorruption())
    }
    
    @Test
    fun `isPasswordError returns true for PasswordAuth error`() {
        val error = AppError.OperationError.PasswordAuth(
            userMessage = "Incorrect password",
            technicalMessage = "Authentication failed"
        )
        assertTrue(error.isPasswordError())
        assertTrue(error.allowsPasswordRetry())
    }
    
    @Test
    fun `isPasswordError returns false for other error types`() {
        val corruptionError = AppError.OperationError.DataCorruption("Data corrupted")
        val fileError = AppError.OperationError.FileNotFound()
        val genericError = AppError.OperationError.GenericOperation("Generic error")
        
        assertFalse(corruptionError.isPasswordError())
        assertFalse(fileError.isPasswordError())
        assertFalse(genericError.isPasswordError())
    }
    
    @Test
    fun `allowsForceDecrypt returns true only for DataCorruption`() {
        val corruptionError = AppError.OperationError.DataCorruption("Data corrupted")
        val passwordError = AppError.OperationError.PasswordAuth("Wrong password")
        val fileError = AppError.OperationError.FileNotFound()
        
        assertTrue(corruptionError.allowsForceDecrypt())
        assertFalse(passwordError.allowsForceDecrypt())
        assertFalse(fileError.allowsForceDecrypt())
    }
    
    @Test
    fun `allowsPasswordRetry returns true only for PasswordAuth`() {
        val corruptionError = AppError.OperationError.DataCorruption("Data corrupted")
        val passwordError = AppError.OperationError.PasswordAuth("Wrong password")
        val fileError = AppError.OperationError.FileNotFound()
        
        assertFalse(corruptionError.allowsPasswordRetry())
        assertTrue(passwordError.allowsPasswordRetry())
        assertFalse(fileError.allowsPasswordRetry())
    }
    
    // fromGoError now classifies on the stable Go error code (see Go errorCode),
    // not on the human-readable message. These tests pin the SECURITY-RELEVANT
    // mapping and the retry affordances it gates.

    @Test
    fun `fromGoError AUTH_FAILED is PasswordAuth allowing retry not force-decrypt`() {
        val error = AppError.fromGoError("The password is incorrect or header is tampered", OperationType.DECRYPT, "AUTH_FAILED")
        assertTrue("Error should be PasswordAuth", error is AppError.OperationError.PasswordAuth)
        assertTrue("AUTH_FAILED must allow password retry", error.allowsPasswordRetry())
        assertFalse("AUTH_FAILED must NOT allow force-decrypt", error.allowsForceDecrypt())
    }

    @Test
    fun `fromGoError DATA_CORRUPTED is DataCorruption allowing force-decrypt not retry`() {
        val error = AppError.fromGoError("data corrupted", OperationType.DECRYPT, "DATA_CORRUPTED")
        assertTrue("Error should be DataCorruption", error is AppError.OperationError.DataCorruption)
        assertTrue("DATA_CORRUPTED must allow force-decrypt", error.allowsForceDecrypt())
        assertFalse("DATA_CORRUPTED must NOT allow password retry", error.allowsPasswordRetry())
    }

    @Test
    fun `fromGoError CORRUPT_HEADER is not DataCorruption and not force-decryptable`() {
        // Header corruption is deliberately NOT force-decryptable (old logic
        // excluded header errors from DataCorruption).
        val error = AppError.fromGoError("header damaged: volume header is damaged", OperationType.DECRYPT, "CORRUPT_HEADER")
        assertFalse("CORRUPT_HEADER must NOT be DataCorruption", error is AppError.OperationError.DataCorruption)
        assertFalse("CORRUPT_HEADER must NOT allow force-decrypt", error.allowsForceDecrypt())
        assertTrue("CORRUPT_HEADER falls through to GenericOperation", error is AppError.OperationError.GenericOperation)
    }

    @Test
    fun `fromGoError CANCELLED is GenericOperation`() {
        val error = AppError.fromGoError("operation cancelled", OperationType.DECRYPT, "CANCELLED")
        assertTrue("CANCELLED falls through to GenericOperation", error is AppError.OperationError.GenericOperation)
        assertFalse(error.allowsForceDecrypt())
        assertFalse(error.allowsPasswordRetry())
    }

    @Test
    fun `fromGoError FILE_NOT_FOUND is FileNotFound`() {
        val error = AppError.fromGoError("file not found", OperationType.DECRYPT, "FILE_NOT_FOUND")
        assertTrue("Error should be FileNotFound", error is AppError.OperationError.FileNotFound)
        assertFalse(error.allowsForceDecrypt())
        assertFalse(error.allowsPasswordRetry())
    }

    @Test
    fun `fromGoError empty code is GenericOperation`() {
        // The synchronous validation-error path passes no code (default "").
        val error = AppError.fromGoError("input file is required", OperationType.ENCRYPT)
        assertTrue("Empty code falls through to GenericOperation", error is AppError.OperationError.GenericOperation)
        assertFalse(error.allowsForceDecrypt())
        assertFalse(error.allowsPasswordRetry())
    }

    @Test
    fun `fromGoError unknown code is GenericOperation`() {
        val error = AppError.fromGoError("Something went wrong", OperationType.DECRYPT, "TOTALLY_UNKNOWN")
        assertTrue("Unknown code falls through to GenericOperation", error is AppError.OperationError.GenericOperation)
    }

    @Test
    fun `fromGoError GENERIC code is GenericOperation`() {
        val error = AppError.fromGoError("Unexpected error", OperationType.DECRYPT, "GENERIC")
        assertTrue("GENERIC code is GenericOperation", error is AppError.OperationError.GenericOperation)
    }

    @Test
    fun `fromGoError preserves error messages`() {
        val userMessage = "Custom error message"
        val error = AppError.fromGoError(userMessage, OperationType.ENCRYPT, "GENERIC")
        assertEquals(userMessage, error.userMessage)
        assertEquals(userMessage, error.technicalMessage)
    }
    
    @Test
    fun `fromException converts file not found exception correctly`() {
        val exception = java.io.FileNotFoundException("File not found: test.txt")
        val error = AppError.fromException(exception)
        
        assertTrue("Error should be FileNotFound", error is AppError.OperationError.FileNotFound)
        assertEquals("File not found: test.txt", error.technicalMessage)
    }
    
    @Test
    fun `fromException converts generic exception correctly`() {
        val exception = RuntimeException("Something went wrong")
        val error = AppError.fromException(exception)
        
        assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        assertEquals("Something went wrong", error.userMessage)
        assertEquals("Something went wrong", error.technicalMessage)
    }
    
    @Test
    fun `fromException handles exception with null message`() {
        val exception = RuntimeException()
        val error = AppError.fromException(exception)
        
        assertTrue("Error should be GenericOperation", error is AppError.OperationError.GenericOperation)
        assertEquals("Unknown error occurred", error.userMessage)
    }
    
    @Test
    fun `ValidationError objects have correct messages`() {
        assertEquals("Please select a file", AppError.ValidationError.NoFileSelected.userMessage)
        assertEquals("Please enter a password", AppError.ValidationError.InvalidPassword.userMessage)
        assertEquals("Passwords do not match", AppError.ValidationError.PasswordsMismatch.userMessage)
    }
    
    @Test
    fun `FileError classes have default messages`() {
        val copyError = AppError.FileError.CopyFailed()
        val deleteError = AppError.FileError.DeleteFailed()
        val saveError = AppError.FileError.SaveFailed()
        
        assertEquals("Failed to copy file", copyError.userMessage)
        assertEquals("Failed to delete file", deleteError.userMessage)
        assertEquals("Failed to save file", saveError.userMessage)
    }
    
    @Test
    fun `FileError classes accept custom messages`() {
        val customMessage = "Custom copy error"
        val error = AppError.FileError.CopyFailed(
            userMessage = customMessage,
            technicalMessage = "Technical details"
        )
        
        assertEquals(customMessage, error.userMessage)
        assertEquals("Technical details", error.technicalMessage)
    }
    
    @Test
    fun `OperationError classes accept custom messages`() {
        val customUserMsg = "User-friendly message"
        val customTechMsg = "Technical details"
        
        val corruptionError = AppError.OperationError.DataCorruption(customUserMsg, customTechMsg)
        val passwordError = AppError.OperationError.PasswordAuth(customUserMsg, customTechMsg)
        val fileError = AppError.OperationError.FileNotFound(customUserMsg, customTechMsg)
        val genericError = AppError.OperationError.GenericOperation(customUserMsg, customTechMsg)
        
        assertEquals(customUserMsg, corruptionError.userMessage)
        assertEquals(customTechMsg, corruptionError.technicalMessage)
        assertEquals(customUserMsg, passwordError.userMessage)
        assertEquals(customTechMsg, passwordError.technicalMessage)
        assertEquals(customUserMsg, fileError.userMessage)
        assertEquals(customTechMsg, fileError.technicalMessage)
        assertEquals(customUserMsg, genericError.userMessage)
        assertEquals(customTechMsg, genericError.technicalMessage)
    }
    
    @Test
    fun `fromGoError ignores message content classifying solely by code`() {
        // Classification is now code-driven and locale-independent: a message that
        // would have tripped the old "password" substring path must NOT be treated
        // as auth unless the code says so. This is the core point of the refactor.
        val asGeneric = AppError.fromGoError("PASSWORD INCORRECT", OperationType.DECRYPT, "GENERIC")
        assertTrue("Message wording must not drive classification", asGeneric is AppError.OperationError.GenericOperation)

        val asAuth = AppError.fromGoError("ничего полезного", OperationType.DECRYPT, "AUTH_FAILED")
        assertTrue("Non-English message still classifies via code", asAuth is AppError.OperationError.PasswordAuth)
        assertTrue(asAuth.allowsPasswordRetry())
    }
}


