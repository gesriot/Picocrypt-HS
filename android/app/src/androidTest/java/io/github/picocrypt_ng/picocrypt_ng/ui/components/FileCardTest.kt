package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.FormData
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for FileCard component.
 */
@RunWith(AndroidJUnit4::class)
class FileCardTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun fileCard_displays_when_no_file_is_selected() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val viewModel = MainViewModel(application, savedStateHandle)

        composeTestRule.setContent {
            ChooseFile(viewModel = viewModel)
        }

        composeTestRule.onRoot().assertIsDisplayed()
    }

    @Test
    fun fileCard_displays_selected_filename() {
        val application = ApplicationProvider.getApplicationContext<android.app.Application>()
        val savedStateHandle = androidx.lifecycle.SavedStateHandle()
        val viewModel = MainViewModel(application, savedStateHandle)

        viewModel.updateFormData(
            FormData(
                selectedFilename = "test.txt",
                copiedFilePath = "/data/test/input_file.txt",
                comments = "",
                passwordInput = CharArray(0),
                confirmPasswordInput = CharArray(0),
                reedSolomon = false,
                paranoid = false,
                deniability = false,
                keyfileFilenames = emptyList(),
                keyfileOrdered = false,
                decryptionInfo = null
            )
        )

        composeTestRule.setContent {
            ChooseFile(viewModel = viewModel)
        }

        composeTestRule.onNodeWithText("test.txt").assertIsDisplayed()
    }
}
