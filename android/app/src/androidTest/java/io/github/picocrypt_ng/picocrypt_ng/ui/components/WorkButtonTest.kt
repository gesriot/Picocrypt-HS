package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.FormData
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for WorkButton component.
 */
@RunWith(AndroidJUnit4::class)
class WorkButtonTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun workButton_displays_encrypt_label() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()

        mainViewModel.updateFormData(
            FormData(
                selectedFilename = "test.txt",
                copiedFilePath = "/data/test/input_file.txt",
                comments = "",
                passwordInput = "secret".toCharArray(),
                confirmPasswordInput = "secret".toCharArray(),
                reedSolomon = false,
                paranoid = false,
                deniability = false,
                keyfileFilenames = emptyList(),
                keyfileOrdered = false,
                decryptionInfo = null
            )
        )

        composeTestRule.setContent {
            WorkButton(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel
            )
        }

        composeTestRule
            .onNodeWithText(application.getString(R.string.encrypt_file))
            .assertIsDisplayed()
    }

    @Test
    fun workButton_displays_decrypt_label() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()

        mainViewModel.updateFormData(
            FormData(
                selectedFilename = "test.pcv",
                copiedFilePath = "/data/test/input_file.pcv",
                comments = "",
                passwordInput = "secret".toCharArray(),
                confirmPasswordInput = "secret".toCharArray(),
                reedSolomon = false,
                paranoid = false,
                deniability = false,
                keyfileFilenames = emptyList(),
                keyfileOrdered = false,
                decryptionInfo = null
            )
        )

        composeTestRule.setContent {
            WorkButton(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel
            )
        }

        composeTestRule
            .onNodeWithText(application.getString(R.string.decrypt_file))
            .assertIsDisplayed()
    }

    @Test
    fun workButton_is_disabled_when_copied_file_path_is_missing() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val mainViewModel = MainViewModel(application, savedStateHandle)
        val operationViewModel = OperationViewModel()

        mainViewModel.updateFormData(
            FormData(
                selectedFilename = "test.txt",
                copiedFilePath = "",
                comments = "",
                passwordInput = "secret".toCharArray(),
                confirmPasswordInput = "secret".toCharArray(),
                reedSolomon = false,
                paranoid = false,
                deniability = false,
                keyfileFilenames = emptyList(),
                keyfileOrdered = false,
                decryptionInfo = null
            )
        )

        composeTestRule.setContent {
            WorkButton(
                mainViewModel = mainViewModel,
                operationViewModel = operationViewModel
            )
        }

        composeTestRule
            .onNodeWithText(application.getString(R.string.encrypt_file))
            .assertIsNotEnabled()
    }
}
