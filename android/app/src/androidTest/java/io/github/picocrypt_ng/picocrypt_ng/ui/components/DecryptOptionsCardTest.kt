package io.github.picocrypt_ng.picocrypt_ng.ui.components

import android.app.Application
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.lifecycle.SavedStateHandle
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.picocrypt_ng.picocrypt_ng.MainViewModel
import io.github.picocrypt_ng.picocrypt_ng.R
import io.github.picocrypt_ng.picocrypt_ng.testutils.TestDataBuilders
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DecryptOptionsCardTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private val application: Application
        get() = ApplicationProvider.getApplicationContext()

    @Test
    fun verifyFirstCheckboxTogglesFormState() {
        val viewModel = MainViewModel(application, SavedStateHandle())
        viewModel.updateFormData(TestDataBuilders.createDecryptFormData())

        composeTestRule.setContent {
            DecryptOptionsCard(viewModel = viewModel)
        }

        // ExpandableCard starts collapsed — expand it (count starts at 0), then toggle.
        composeTestRule.onNodeWithText(application.getString(R.string.decrypt_options, 0)).performClick()
        composeTestRule.onNodeWithText(application.getString(R.string.verify_first)).performClick()

        assertTrue(
            "Tapping 'verify first' must flip the verifyFirst form state",
            viewModel.formState.value.verifyFirst
        )
    }
}
