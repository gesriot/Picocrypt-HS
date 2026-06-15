package io.github.picocrypt_ng.picocrypt_ng

import android.content.SharedPreferences
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for SettingsRepository.
 *
 * Built via the internal constructor with a mockk'd SharedPreferences so the
 * persistence behavior can be asserted without a device or Robolectric.
 */
class SettingsRepositoryTest {

    private lateinit var editor: SharedPreferences.Editor
    private lateinit var prefs: SharedPreferences

    @Before
    fun setUp() {
        editor = mockk<SharedPreferences.Editor>(relaxed = true)
        prefs = mockk<SharedPreferences>()
        every { prefs.edit() } returns editor
        every { editor.putBoolean(any(), any()) } returns editor
        every { editor.apply() } just Runs
    }

    @Test
    fun `screenshotProtectionEnabled defaults to true and is seeded from prefs`() {
        every { prefs.getBoolean(SettingsRepository.KEY, true) } returns true

        val repo = SettingsRepository(prefs)

        // Asserts the production default is true. Fails if the default is flipped
        // to false, because the seed read passes `true` as the prefs fallback.
        assertEquals(true, repo.screenshotProtectionEnabled.value)
        verify { prefs.getBoolean(SettingsRepository.KEY, true) }
    }

    @Test
    fun `setScreenshotProtectionEnabled false persists and updates state`() {
        every { prefs.getBoolean(SettingsRepository.KEY, true) } returns true
        val repo = SettingsRepository(prefs)

        repo.setScreenshotProtectionEnabled(false)

        verify { editor.putBoolean(SettingsRepository.KEY, false) }
        verify { editor.apply() }
        assertEquals(false, repo.screenshotProtectionEnabled.value)
    }

    @Test
    fun `setScreenshotProtectionEnabled true round-trips from a false seed`() {
        every { prefs.getBoolean(SettingsRepository.KEY, true) } returns false
        val repo = SettingsRepository(prefs)
        assertEquals(false, repo.screenshotProtectionEnabled.value)

        repo.setScreenshotProtectionEnabled(true)

        verify { editor.putBoolean(SettingsRepository.KEY, true) }
        verify { editor.apply() }
        assertEquals(true, repo.screenshotProtectionEnabled.value)
    }
}
