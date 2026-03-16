package io.github.picocrypt_ng.picocrypt_ng

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UI tests for MainActivity covering complete user flows.
 */
@RunWith(AndroidJUnit4::class)
class MainActivityUITest {
    
    @get:Rule
    val composeTestRule = createAndroidComposeRule<MainActivity>()
    
    @Test
    fun mainActivity_displays_on_launch() {
        composeTestRule.onRoot().assertIsDisplayed()
    }
    
    @Test
    fun mainActivity_displays_logo_and_file_selection_ui() {
        composeTestRule.onNodeWithContentDescription("logo icon").assertIsDisplayed()
        composeTestRule.onNodeWithContentDescription("logo text").assertIsDisplayed()
        composeTestRule.onNodeWithContentDescription("Choose file").assertIsDisplayed()
        composeTestRule.onNodeWithText("Choose a file").assertIsDisplayed()
    }
    
    @Test
    fun mainActivity_hides_work_buttons_before_file_selection() {
        composeTestRule.onAllNodesWithText("Encrypt File").assertCountEquals(0)
        composeTestRule.onAllNodesWithText("Decrypt File").assertCountEquals(0)
    }
}
