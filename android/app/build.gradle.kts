import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    id("kotlin-parcelize")
}

val releaseSigningRequested = gradle.startParameter.taskNames.any { task ->
    val lower = task.lowercase()
    lower.contains("assemblerelease") ||
        lower.contains("bundlerelease") ||
        lower.contains("packagerelease")
}

val releaseSigningProps = mapOf(
    "PICOCRYPT_KEYSTORE_PATH" to providers.gradleProperty("PICOCRYPT_KEYSTORE_PATH").orNull,
    "PICOCRYPT_KEYSTORE_PASSWORD" to providers.gradleProperty("PICOCRYPT_KEYSTORE_PASSWORD").orNull,
    "PICOCRYPT_KEY_ALIAS" to providers.gradleProperty("PICOCRYPT_KEY_ALIAS").orNull,
    "PICOCRYPT_KEY_PASSWORD" to providers.gradleProperty("PICOCRYPT_KEY_PASSWORD").orNull,
)

val releaseSigningConfigured = releaseSigningProps.values.none { it.isNullOrBlank() }

android {
    namespace = "io.github.picocrypt_ng.picocrypt_ng"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.picocrypt_ng.picocrypt_ng"
        minSdk = 24
        targetSdk = 36
        versionCode = providers
            .gradleProperty("PICOCRYPT_VERSION_CODE")
            .map(String::toInt)
            .orElse(1)
            .get()
        versionName = providers
            .gradleProperty("PICOCRYPT_VERSION_NAME")
            .orElse("dev")
            .get()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseSigningConfigured) {
            create("release") {
                storeFile = file(releaseSigningProps.getValue("PICOCRYPT_KEYSTORE_PATH")!!)
                storePassword = releaseSigningProps.getValue("PICOCRYPT_KEYSTORE_PASSWORD")
                keyAlias = releaseSigningProps.getValue("PICOCRYPT_KEY_ALIAS")
                keyPassword = releaseSigningProps.getValue("PICOCRYPT_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            if (releaseSigningConfigured) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
    packaging {
        resources {
            excludes += setOf(
                "META-INF/LICENSE.md",
                "META-INF/LICENSE-notice.md",
            )
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

if (releaseSigningRequested && !releaseSigningConfigured) {
    throw GradleException(
        "Missing Android release signing properties. Expected PICOCRYPT_KEYSTORE_PATH, " +
            "PICOCRYPT_KEYSTORE_PASSWORD, PICOCRYPT_KEY_ALIAS, and PICOCRYPT_KEY_PASSWORD."
    )
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.animation.lint)
    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.androidx.arch.core.testing)
    // JSONObject for unit tests (Android's org.json is not available in unit tests)
    testImplementation("org.json:json:20240303")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    androidTestImplementation(libs.mockk)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)

    implementation(libs.androidx.material.icons.extended)
    implementation(libs.kotlinx.coroutines.android)
    
    // Go Mobile bindings (built separately with build-gomobile.sh)
    implementation(files("libs/picocrypt-mobile.aar"))
}
