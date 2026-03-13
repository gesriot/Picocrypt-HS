package io.github.picocrypt_ng.picocrypt_ng.ui.components

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.OperationViewModel
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
    fun `ProgressCard composes with no active operation`() {
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
}
