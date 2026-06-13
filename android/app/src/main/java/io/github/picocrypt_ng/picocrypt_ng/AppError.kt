package io.github.picocrypt_ng.picocrypt_ng

/**
 * Sealed hierarchy for all application errors.
 * Provides type-safe error handling with user-friendly messages.
 * Extends Exception to be compatible with Result.failure().
 */
sealed class AppError(
    /**
     * User-friendly error message to display in UI.
     */
    val userMessage: String,
    /**
     * Optional technical message for logging/debugging.
     */
    val technicalMessage: String? = null
) : Exception(userMessage) {
    
    /**
     * Checks if this is a data corruption error (for force decrypt option).
     */
    fun isDataCorruption(): Boolean = this is OperationError.DataCorruption
    
    /**
     * Checks if this is a password or authentication error (for retry option).
     */
    fun isPasswordError(): Boolean = this is OperationError.PasswordAuth
    
    /**
     * Checks if this error allows retry with force decrypt.
     */
    fun allowsForceDecrypt(): Boolean = isDataCorruption()
    
    /**
     * Checks if this error allows retry with new password.
     */
    fun allowsPasswordRetry(): Boolean = isPasswordError()
    
    /**
     * Operation-related errors from encryption/decryption operations.
     */
    sealed class OperationError(
        userMessage: String,
        technicalMessage: String? = null
    ) : AppError(userMessage, technicalMessage) {
        /**
         * Data corruption detected during decryption.
         * Allows force decrypt option.
         */
        class DataCorruption(
            userMessage: String,
            technicalMessage: String? = null
        ) : OperationError(userMessage, technicalMessage)
        
        /**
         * Password or keyfile authentication failed.
         * Allows retry with new password.
         */
        class PasswordAuth(
            userMessage: String,
            technicalMessage: String? = null
        ) : OperationError(userMessage, technicalMessage)
        
        /**
         * File not found or inaccessible.
         */
        class FileNotFound(
            userMessage: String = "File not found or inaccessible",
            technicalMessage: String? = null
        ) : OperationError(userMessage, technicalMessage)
        
        /**
         * Generic operation error.
         */
        class GenericOperation(
            userMessage: String,
            technicalMessage: String? = null
        ) : OperationError(userMessage, technicalMessage)
    }
    
    /**
     * File operation errors (copy, save, delete).
     */
    sealed class FileError(
        userMessage: String,
        technicalMessage: String? = null
    ) : AppError(userMessage, technicalMessage) {
        /**
         * Failed to copy file to internal storage.
         */
        class CopyFailed(
            userMessage: String = "Failed to copy file",
            technicalMessage: String? = null
        ) : FileError(userMessage, technicalMessage)
        
        /**
         * Failed to delete file.
         */
        class DeleteFailed(
            userMessage: String = "Failed to delete file",
            technicalMessage: String? = null
        ) : FileError(userMessage, technicalMessage)
        
        /**
         * Failed to save file to user-selected location.
         */
        class SaveFailed(
            userMessage: String = "Failed to save file",
            technicalMessage: String? = null
        ) : FileError(userMessage, technicalMessage)
    }
    
    /**
     * Form validation errors.
     */
    sealed class ValidationError(
        userMessage: String
    ) : AppError(userMessage) {
        /**
         * No file selected.
         */
        object NoFileSelected : ValidationError("Please select a file")
        
        /**
         * Invalid password (empty or doesn't meet requirements).
         */
        object InvalidPassword : ValidationError("Please enter a password")
        
        /**
         * Passwords don't match (for encryption).
         */
        object PasswordsMismatch : ValidationError("Passwords do not match")
    }
    
    companion object {
        /**
         * Converts a Go error into a typed AppError using the stable, locale-independent
         * [code] emitted by the Go layer (see Go errorCode), NOT the human-readable
         * [errorString]. This replaces the prior fragile substring matching on Go error
         * text, which was locale-coupled and tightly bound to Go wording.
         *
         * SECURITY: the mapping gates retry affordances and must preserve the old
         * semantics exactly:
         *  - AUTH_FAILED   -> PasswordAuth   : allowsPasswordRetry, NOT force-decrypt
         *                    (wrong password / failed authentication / wrong keyfiles).
         *  - DATA_CORRUPTED-> DataCorruption : allowsForceDecrypt (force-decrypt BYPASSES
         *                    integrity/RS checks; only offered for recoverable payload
         *                    corruption).
         *  - CORRUPT_HEADER/CANCELLED/unknown -> GenericOperation : header corruption is
         *                    deliberately NOT force-decryptable (the old logic excluded
         *                    header errors from DataCorruption).
         *
         * [code] defaults to "" so the synchronous validation-error path
         * (GoBridge.startEncrypt/startDecrypt) keeps working -> GenericOperation.
         * [operationType] is retained for call-site clarity and future use.
         */
        fun fromGoError(errorString: String, operationType: OperationType, code: String = ""): AppError {
            return when (code) {
                "AUTH_FAILED" -> OperationError.PasswordAuth(
                    userMessage = errorString,
                    technicalMessage = errorString
                )
                "DATA_CORRUPTED" -> OperationError.DataCorruption(
                    userMessage = errorString,
                    technicalMessage = errorString
                )
                "FILE_NOT_FOUND" -> OperationError.FileNotFound(
                    technicalMessage = errorString
                )
                else -> OperationError.GenericOperation(
                    userMessage = errorString,
                    technicalMessage = errorString
                )
            }
        }
        
        /**
         * Converts an Exception to an AppError.
         */
        fun fromException(exception: Exception): AppError {
            val message = exception.message ?: "Unknown error occurred"
            val errorLower = message.lowercase()
            
            if (errorLower.contains("file not found") || 
                errorLower.contains("no such file")) {
                return OperationError.FileNotFound(
                    technicalMessage = message
                )
            }
            
            return OperationError.GenericOperation(
                userMessage = message,
                technicalMessage = message
            )
        }
    }
}

