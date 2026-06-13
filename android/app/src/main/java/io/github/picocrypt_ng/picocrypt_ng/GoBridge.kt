package io.github.picocrypt_ng.picocrypt_ng

import android.os.Parcelable
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.parcelize.Parcelize
import mobile.Mobile
import mobile.ProgressResult as GoProgressResult
import org.json.JSONArray
import org.json.JSONObject

/**
 * Options for encryption operations.
 * This is the Kotlin representation of the Go EncryptOptions struct.
 */
data class EncryptOptions(
    val comments: String = "",
    val paranoid: Boolean = false,
    val reedSolomon: Boolean = false,
    val deniability: Boolean = false,
    val compress: Boolean = false,
    val keyfiles: List<String> = emptyList(),
    val keyfileOrdered: Boolean = false
)

/**
 * Options for decryption operations.
 * This is the Kotlin representation of the Go DecryptOptions struct.
 */
data class DecryptOptions(
    val keyfiles: List<String> = emptyList(),
    val forceDecrypt: Boolean = false,
    val verifyFirst: Boolean = false,
    val autoUnzip: Boolean = false,
    val sameLevel: Boolean = false,
    val recombine: Boolean = false,
    val deniability: Boolean = false
)

/**
 * Decryption metadata information.
 * This contains encryption settings and requirements that can be read
 * from an encrypted file without decrypting it.
 */
@Parcelize
data class DecryptionInfo(
    val keyfilesRequired: Boolean,
    val keyfileOrdered: Boolean,
    val reedSolomon: Boolean,
    val deniability: Boolean,
    val paranoid: Boolean,
    val comments: String,
    val readable: Boolean // false if deniable (can't read other fields without password)
) : Parcelable

/**
 * Progress state for an operation.
 * This is the Kotlin representation of the Go ProgressResult struct.
 */
data class ProgressState(
    val status: String,
    val progress: Float,
    val info: String,
    val done: Boolean,
    /**
     * Stable, locale-independent error classification emitted by Go (see Go
     * errorCode); empty unless the operation failed. Drives AppError.fromGoError
     * instead of fragile substring matching on [info].
     */
    val code: String = ""
)

/**
 * Kotlin wrapper for Go mobile bindings.
 * 
 * This bridge connects the Android app to the Go encryption backend
 * through gomobile bindings. The Go mobile package provides all
 * encryption/decryption functionality.
 */
object GoBridge {
    /**
     * Starts a new operation and returns its ID.
     * This should be called before StartEncrypt or StartDecrypt.
     */
    fun startOperation(): String {
        return try {
            Mobile.startOperation()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Generate a fallback ID if Go binding fails
            "op_${System.currentTimeMillis()}"
        }
    }
    
    /**
     * Detects if a file should be encrypted or decrypted.
     * @param filePath Path to the file to check
     * @return Result containing true for encrypt, false for decrypt, or error if detection fails
     */
    fun detectOperation(filePath: String): Result<Boolean> {
        return try {
            val result = Mobile.detectOperation(filePath)
            Result.success(result)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Return error instead of fallback - Go binding failure is a critical error
            Result.failure(
                AppError.OperationError.GenericOperation(
                    userMessage = "Failed to detect operation type: ${e.message ?: "Unknown error"}",
                    technicalMessage = "Go binding error: ${e.message ?: e.toString()}"
                )
            )
        }
    }
    
    /**
     * Starts an encryption operation in the background.
     * 
     * @param operationID Operation ID from startOperation()
     * @param inputFile Path to input file
     * @param outputFile Path to output file
     * @param password Password for encryption as UTF-8 bytes; zeroed before this returns
     * @param options Encryption options
     * @return Result indicating success or failure
     */
    fun startEncrypt(
        operationID: String,
        inputFile: String,
        outputFile: String,
        password: ByteArray,
        options: EncryptOptions
    ): Result<Unit> {
        return try {
            // Build JSON request (password is passed separately as bytes, never in JSON)
            val requestJson = JSONObject().apply {
                put("operationID", operationID)
                put("inputFile", inputFile)
                put("outputFile", outputFile)
                put("comments", options.comments)
                put("keyfiles", JSONArray().apply {
                    options.keyfiles.forEach { put(it) }
                })
                put("paranoid", options.paranoid)
                put("reedSolomon", options.reedSolomon)
                put("deniability", options.deniability)
                put("compress", options.compress)
                put("keyfileOrdered", options.keyfileOrdered)
            }.toString()

            // Note: gomobile copies the array across JNI; that transient bridge copy is not reachable for zeroing (intrinsic to the binding).
            val errorMsg = Mobile.startEncrypt(requestJson, password)

            if (errorMsg.isNotEmpty()) {
                // Convert Go error to AppError (operation type unknown here, use generic)
                val appError = AppError.fromGoError(errorMsg, OperationType.ENCRYPT)
                Result.failure(appError)
            } else {
                Result.success(Unit)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        } finally {
            password.fill(0)
        }
    }
    
    /**
     * Starts a decryption operation in the background.
     * 
     * @param operationID Operation ID from startOperation()
     * @param inputFile Path to input file
     * @param outputFile Path to output file
     * @param password Password for decryption as UTF-8 bytes; zeroed before this returns
     * @param options Decryption options
     * @return Result indicating success or failure
     */
    fun startDecrypt(
        operationID: String,
        inputFile: String,
        outputFile: String,
        password: ByteArray,
        options: DecryptOptions
    ): Result<Unit> {
        return try {
            // Build JSON request (password is passed separately as bytes, never in JSON)
            val requestJson = JSONObject().apply {
                put("operationID", operationID)
                put("inputFile", inputFile)
                put("outputFile", outputFile)
                put("keyfiles", JSONArray().apply {
                    options.keyfiles.forEach { put(it) }
                })
                put("forceDecrypt", options.forceDecrypt)
                put("verifyFirst", options.verifyFirst)
                put("autoUnzip", options.autoUnzip)
                put("sameLevel", options.sameLevel)
                put("recombine", options.recombine)
                put("deniability", options.deniability)
            }.toString()

            // Note: gomobile copies the array across JNI; that transient bridge copy is not reachable for zeroing (intrinsic to the binding).
            val errorMsg = Mobile.startDecrypt(requestJson, password)

            if (errorMsg.isNotEmpty()) {
                // Convert Go error to AppError
                val appError = AppError.fromGoError(errorMsg, OperationType.DECRYPT)
                Result.failure(appError)
            } else {
                Result.success(Unit)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        } finally {
            password.fill(0)
        }
    }
    
    /**
     * Gets the current progress state for an operation.
     * 
     * @param operationID Operation ID to get progress for
     * @return Result containing ProgressState or error
     */
    fun getProgress(operationID: String): Result<ProgressState> {
        return try {
            val result: GoProgressResult = Mobile.getProgress(operationID)
            
            // If there's an error, include it in the info field (OperationManager expects this)
            val error = result.getError()
            val info = if (error != null && error.isNotEmpty()) {
                error
            } else {
                result.getInfo() ?: ""
            }
            
            // Convert Go ProgressResult to Kotlin ProgressState
            Result.success(ProgressState(
                status = result.getStatus() ?: "Unknown",
                progress = result.getProgress(),
                info = info,
                done = result.getDone(),
                code = result.getCode() ?: ""
            ))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
    
    /**
     * Cancels a running operation.
     * 
     * @param operationID Operation ID to cancel
     * @return Result indicating success or failure
     */
    fun cancelOperation(operationID: String): Result<Unit> {
        return try {
            Mobile.cancelOperation(operationID)
            Result.success(Unit)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
    
    /**
     * Gets decryption metadata from an encrypted file without decrypting it.
     * This allows the app to determine what credentials and settings were used
     * during encryption.
     * 
     * @param filePath Path to the encrypted file
     * @return Result containing DecryptionInfo or error
     */
    fun getDecryptionInfo(filePath: String): Result<DecryptionInfo> {
        return try {
            val jsonString = Mobile.getDecryptionInfo(filePath)
            val json = JSONObject(jsonString)
            
            Result.success(DecryptionInfo(
                keyfilesRequired = json.getBoolean("keyfilesRequired"),
                keyfileOrdered = json.getBoolean("keyfileOrdered"),
                reedSolomon = json.getBoolean("reedSolomon"),
                deniability = json.getBoolean("deniability"),
                paranoid = json.getBoolean("paranoid"),
                comments = json.getString("comments"),
                readable = json.getBoolean("readable")
            ))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Result.failure(AppError.fromException(e))
        }
    }
}
