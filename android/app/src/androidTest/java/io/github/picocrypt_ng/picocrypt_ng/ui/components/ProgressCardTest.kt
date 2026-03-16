package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.AppError
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationManager
import io.github.picocrypt_ng.picocrypt_ng.OperationState
import io.github.picocrypt_ng.picocrypt_ng.OperationType
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for ProgressCard component.
 */
@RunWith(AndroidJUnit4::class)
class ProgressCardTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun progressCard_composes_with_no_active_operation() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()

        composeTestRule.setContent {
            ProgressCard(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel
            )
        }

        composeTestRule.onRoot().assertIsDisplayed()
    }

    @Test
    fun progressCard_shows_retry_dialog_for_password_errors() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()
        val originalState = swapOperationState(
            TestDataBuilders.createOperationState(
                type = OperationType.DECRYPT,
                done = true,
                error = AppError.OperationError.PasswordAuth("Incorrect password"),
                formData = TestDataBuilders.createDecryptFormData()
            )
        )

        try {
            composeTestRule.setContent {
                ProgressCard(
                    mainViewModel = mainViewModel,
                    operationViewModel = operationViewModel
                )
            }

            composeTestRule.onNodeWithText(application.getString(R.string.retry)).assertIsDisplayed()
            composeTestRule.onNodeWithText(application.getString(R.string.cancel)).assertIsDisplayed()
            composeTestRule.onNodeWithText("Incorrect password").assertIsDisplayed()
        } finally {
            restoreOperationState(originalState)
        }
    }

    @Test
    fun progressCard_shows_force_decrypt_dialog_for_corruption_errors() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()
        val originalState = swapOperationState(
            TestDataBuilders.createOperationState(
                type = OperationType.DECRYPT,
                done = true,
                error = AppError.OperationError.DataCorruption("Ciphertext corrupted"),
                formData = TestDataBuilders.createDecryptFormData()
            )
        )

        try {
            composeTestRule.setContent {
                ProgressCard(
                    mainViewModel = mainViewModel,
                    operationViewModel = operationViewModel
                )
            }

            composeTestRule.onNodeWithText(application.getString(R.string.force_decrypt)).assertIsDisplayed()
            composeTestRule.onNodeWithText(application.getString(R.string.cancel)).assertIsDisplayed()
            composeTestRule.onNodeWithText(application.getString(R.string.data_corruption_detected)).assertIsDisplayed()
            composeTestRule.onNodeWithText("Ciphertext corrupted").assertIsDisplayed()
        } finally {
            restoreOperationState(originalState)
        }
    }
}

private fun swapOperationState(state: OperationState?): MutableStateFlow<OperationState?> {
    val field = OperationManager::class.java.getDeclaredField("_currentOperation")
    field.isAccessible = true
    @Suppress("UNCHECKED_CAST")
    val flow = field.get(OperationManager) as MutableStateFlow<OperationState?>
    val original = MutableStateFlow(flow.value)
    flow.value = state
    return original
}

private fun restoreOperationState(original: MutableStateFlow<OperationState?>) {
    val field = OperationManager::class.java.getDeclaredField("_currentOperation")
    field.isAccessible = true
    @Suppress("UNCHECKED_CAST")
    val flow = field.get(OperationManager) as MutableStateFlow<OperationState?>
    flow.value = original.value
}
