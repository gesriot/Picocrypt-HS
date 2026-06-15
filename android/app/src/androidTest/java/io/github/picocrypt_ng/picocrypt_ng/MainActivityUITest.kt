package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.view.WindowManager
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExternalResource
import org.junit.rules.RuleChain
import org.junit.runner.RunWith

/**
 * UI tests for MainActivity covering complete user flows, including the
 * screenshot-protection (FLAG_SECURE) behavior.
 */
@RunWith(AndroidJUnit4::class)
class MainActivityUITest {

    // createAndroidComposeRule launches MainActivity when the rule is APPLIED, which happens
    // before any @Before method runs. The default screenshot-protection setting is ON, and
    // MainActivity.onCreate adds FLAG_SECURE before setContent based on that setting — so to
    // assert the launch-time default-ON behavior we MUST reset prefs + the SettingsRepository
    // singleton BEFORE the activity launches. A plain @Before is too late. The RuleChain below
    // wraps the compose rule in an outer ExternalResource whose before() runs first, guaranteeing
    // a clean, default-ON state at launch. commit() (not apply()) so the write is durable before
    // the activity reads it.
    // NOTE: intentionally NOT annotated @get:Rule — it is applied via `ruleChain` below. Adding
    // @get:Rule here would apply it twice and break the outer-rule-runs-first ordering.
    private val composeTestRule = createAndroidComposeRule<MainActivity>()

    @get:Rule
    val ruleChain: RuleChain = RuleChain
        .outerRule(object : ExternalResource() {
            override fun before() {
                clearSettings()
            }
        })
        .around(composeTestRule)

    @After
    fun tearDown() {
        // Don't leak this class's prefs/singleton state into other test classes in the suite.
        clearSettings()
    }

    private fun clearSettings() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        ctx.getSharedPreferences(SettingsRepository.PREFS_NAME, Context.MODE_PRIVATE)
            .edit().clear().commit()
        SettingsRepository.resetForTest()
    }

    // Reads the live window LayoutParams each call (not a stale capture).
    private fun secureFlag(): Int =
        composeTestRule.activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE

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

    @Test
    fun chooseFileRow_folderIcon_doesNotMoveWhenMenuOpens() {
        // Regression: the folder icon used to jump from the right edge toward the center when the
        // "Choose a file" dropdown opened, because the DropdownMenu was a third child of the
        // SpaceBetween Row (its zero-size popup anchor became an arrangement participant). The
        // icon's bounds must be identical before and after the menu opens.
        val before = composeTestRule.onNodeWithContentDescription("Choose file")
            .getUnclippedBoundsInRoot()
        composeTestRule.onNodeWithText("Choose a file").performClick()
        composeTestRule.waitForIdle()
        composeTestRule.onNodeWithText("Single file").assertIsDisplayed() // menu actually opened
        val after = composeTestRule.onNodeWithContentDescription("Choose file")
            .getUnclippedBoundsInRoot()
        assertEquals("folder icon must not shift when the dropdown opens", before, after)
    }

    @Test
    fun mainActivity_appliesFlagSecure_atLaunch_underDefaultOn() {
        // The default setting is ON, so the cold-start frame must already be secure: a leaked
        // first frame in the recents thumbnail would defeat the whole feature. We cleared prefs
        // pre-launch, so this asserts the default, not a persisted value.
        assertNotEquals(
            "FLAG_SECURE must be set on the activity window at launch under default-ON",
            0,
            secureFlag()
        )
    }

    @Test
    fun mainActivity_clearsFlagSecure_whenProtectionToggledOff() {
        // Sanity: we start secure (default-ON).
        assertNotEquals(
            "precondition: FLAG_SECURE should be set before toggling off",
            0,
            secureFlag()
        )

        // Toggle the setting off via the real checkbox the user taps.
        composeTestRule.onNodeWithText("Prevent screenshots").performClick()

        // The window flag is updated by MainActivity's lifecycleScope StateFlow collector, which
        // runs OFF the Compose clock — Compose idleness does NOT guarantee it has fired yet.
        // Poll the actual window flag until the collector clears it.
        composeTestRule.waitUntil(timeoutMillis = 5_000) { secureFlag() == 0 }

        assertEquals(
            "FLAG_SECURE must be cleared after the user disables screenshot protection",
            0,
            secureFlag()
        )
    }

    // TODO(dialog-inheritance guard): With protection ON, an AlertDialog hosted by MainActivity
    // (ErrorDialog / ProgressCard / KeyfileCard) should inherit FLAG_SECURE so dialog content is
    // not captured in screenshots — this guards the implicit securePolicy=Inherit against a
    // future SecureOff regression. Deferred because none of these dialogs can be opened from a
    // pure UI test without driving a backend Go operation or an error/file-pick flow (which
    // requires a SAF file pick or a started operation that isn't reliably reproducible in an
    // instrumented UI test). Faking a dialog would not exercise the real securePolicy path, so
    // per task guidance we document the intended assertion instead of asserting on a fake. The
    // intended check, once a dialog can be opened simply:
    //   val dialogWindow = /* the AlertDialog's Window */
    //   assertNotEquals(0, dialogWindow.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE)
}
