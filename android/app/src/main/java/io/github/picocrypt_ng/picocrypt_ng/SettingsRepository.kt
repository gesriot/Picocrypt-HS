package io.github.picocrypt_ng.picocrypt_ng

import android.content.Context
import android.content.SharedPreferences
import androidx.annotation.VisibleForTesting
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * SharedPreferences-backed, process-singleton, reactive holder for the
 * screenshot-protection setting.
 *
 * The StateFlow is seeded eagerly in the constructor so a caller reading
 * `.value` immediately after [getInstance] (on cold start) gets the persisted
 * value rather than a placeholder.
 */
class SettingsRepository @VisibleForTesting internal constructor(
    private val prefs: SharedPreferences
) {
    private val _screenshotProtectionEnabled =
        MutableStateFlow(prefs.getBoolean(KEY, DEFAULT_SCREENSHOT_PROTECTION))
    val screenshotProtectionEnabled: StateFlow<Boolean> =
        _screenshotProtectionEnabled.asStateFlow()

    fun setScreenshotProtectionEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY, enabled).apply()
        _screenshotProtectionEnabled.value = enabled
    }

    companion object {
        const val PREFS_NAME = "picocrypt_settings"
        const val KEY = "screenshot_protection_enabled"
        private const val DEFAULT_SCREENSHOT_PROTECTION = true

        @Volatile
        private var instance: SettingsRepository? = null

        /**
         * Returns the process-wide singleton, constructing it on first call from
         * `applicationContext`. The singleton's identity is independent of the
         * per-call [context], so MainActivity and a Compose MainLayout observe the
         * same backing StateFlow.
         */
        fun getInstance(context: Context): SettingsRepository {
            return instance ?: synchronized(this) {
                instance ?: SettingsRepository(
                    context.applicationContext
                        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                ).also { instance = it }
            }
        }

        /**
         * Drops the cached singleton so the next [getInstance] re-seeds from prefs.
         * Used by instrumented test teardown; clearing the prefs file alone is
         * insufficient because the StateFlow is seeded only once at construction.
         */
        @VisibleForTesting
        fun resetForTest() = synchronized(this) {
            instance = null
        }
    }
}
