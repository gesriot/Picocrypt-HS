package io.github.picocrypt_ng.picocrypt_ng

/** Exhaustive UI state for an encrypt/decrypt operation. */
sealed interface OperationUiState {
    data object Idle : OperationUiState
    data class Running(
        val type: OperationType,
        val progress: Float,
        val status: String,
        val info: String,
    ) : OperationUiState
    data class Success(val type: OperationType) : OperationUiState
    data class Failed(val type: OperationType, val error: AppError) : OperationUiState
}

/**
 * Projects the polled [OperationState] (source of truth from the Go bridge) into the exhaustive
 * [OperationUiState] consumed by the UI. This replaces the prior done/error/magic-status boolean
 * machine.
 *
 * Behaviour is preserved exactly from the old ProgressCard branches:
 *  - null            -> Idle    (no operation)
 *  - !done           -> Running (operation in progress; cancel affordance)
 *  - done && error   -> Failed  (carries the full AppError so ProgressCard can gate the
 *                                force-decrypt (DataCorruption) and password-retry (PasswordAuth)
 *                                buttons via allowsForceDecrypt()/allowsPasswordRetry())
 *  - done && !error  -> Success (the "Completed" save dialog)
 *
 * NOTE on cancel: OperationManager.cancelOperation() leaves the state at done=true, error=null
 * (status="Cancelled"). The old ProgressCard's showSuccess = done && error == null therefore
 * rendered the success/save dialog for a cancelled op, so "Cancelled" maps to Success here to
 * preserve that exact UX rather than collapsing to Idle.
 */
fun OperationState?.toUiState(): OperationUiState = when {
    this == null -> OperationUiState.Idle
    !done -> OperationUiState.Running(type, progress, status, info)
    error != null -> OperationUiState.Failed(type, error)
    else -> OperationUiState.Success(type)
}
