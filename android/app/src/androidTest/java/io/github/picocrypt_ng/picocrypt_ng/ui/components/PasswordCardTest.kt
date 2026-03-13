package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.app.Application
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
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
    fun `PasswordCard displays for encryption`() {
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

    @Test
    fun `password fields are not restored after saved state restore`() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val viewModel = MainViewModel(application, SavedStateHandle())
        val restorationTester = StateRestorationTester(composeTestRule)
        val password = "secret-pass"

        viewModel.updateFormData(
            TestDataBuilders.createEncryptFormData(
                password = "",
                confirmPassword = ""
            )
        )

        composeTestRule.mainClock.autoAdvance = false
        restorationTester.setContent {
            PasswordCard(viewModel = viewModel)
        }

        composeTestRule.onNodeWithText(application.getString(R.string.password)).performTextInput(password)
        composeTestRule.onNodeWithText(application.getString(R.string.confirm_password)).performTextInput(password)
        composeTestRule.onAllNodesWithContentDescription(application.getString(R.string.show_password))[0].performClick()
        composeTestRule.onAllNodesWithText(password).assertCountEquals(2)

        restorationTester.emulateSavedInstanceStateRestore()

        composeTestRule.onAllNodesWithText(password).assertCountEquals(0)
    }
}
