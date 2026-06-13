package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.app.Application
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.lifecycle.SavedStateHandle
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for PasswordCard component.
 */
@RunWith(AndroidJUnit4::class)
class PasswordCardTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun passwordCard_displays_for_encryption() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())

        viewModel.updateFormData(
            TestDataBuilders.createEncryptFormData(
                password = "",
                confirmPassword = ""
            )
        )

        composeTestRule.setContent {
            PasswordCard(viewModel = viewModel)
        }

        composeTestRule.onAllNodesWithText(application.getString(R.string.password)).assertCountEquals(1)
        composeTestRule.onAllNodesWithText(application.getString(R.string.confirm_password)).assertCountEquals(1)
    }
}
