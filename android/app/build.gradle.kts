import org.gradle.util.internal.GUtil
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
}

val playIntegrityPropertiesFile = project.file("play-integrity.properties")
val playIntegrityProperties: Properties = if (playIntegrityPropertiesFile.exists()) {
    GUtil.loadProperties(playIntegrityPropertiesFile)
} else {
    Properties()
}

// https://docs.gradle.org/8.2/userguide/configuration_cache.html#config_cache:requirements:external_processes
val commitHash = providers.exec {
    commandLine("git", "rev-parse", "--short", "HEAD")
}.standardOutput.asText.get().trim()

android {
    namespace = "dev.keiji.deviceintegrity"
    compileSdk = libs.versions.androidCompileSdk.get().toInt()

    signingConfigs {
        getByName("debug") {
            storeFile = rootProject.file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
        create("release") {
            val keystorePropertiesFile = rootProject.file("keystore.properties")
            if (keystorePropertiesFile.exists()) {
                println("Info: Using keystore.properties for release signing.")
                val keystoreProperties = GUtil.loadProperties(keystorePropertiesFile)
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            } else {
                println("Warning: keystore.properties not found. Falling back to debug.keystore for release build.")
                // Fallback to debug keystore if keystore.properties is not found
                storeFile = signingConfigs.getByName("debug").storeFile
                storePassword = signingConfigs.getByName("debug").storePassword
                keyAlias = signingConfigs.getByName("debug").keyAlias
                keyPassword = signingConfigs.getByName("debug").keyPassword
            }
        }
    }

    defaultConfig {
        applicationId = "dev.keiji.deviceintegrity"
        minSdk = libs.versions.androidMinSdk.get().toInt()
        targetSdk = libs.versions.androidTargetSdk.get().toInt()
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // TODO: Replace 0L with your actual Google Cloud Project Number
        buildConfigField("Long", "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", playIntegrityProperties.getProperty("PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", "0L"))
        buildConfigField("String", "PLAY_INTEGRITY_BASE_URL", "\"${playIntegrityProperties.getProperty("PLAY_INTEGRITY_BASE_URL", "http://localhost/")}\"")
        buildConfigField("String", "KEY_ATTESTATION_BASE_URL", "\"${playIntegrityProperties.getProperty("KEY_ATTESTATION_BASE_URL", "http://localhost/")}\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
            versionNameSuffix = "-$commitHash"
        }
        debug {
            versionNameSuffix = "-$commitHash"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        buildConfig = true
    }
}

dependencies {
    implementation(project(":ui:main"))
    implementation(project(":ui:license"))
    implementation(project(":ui:api-endpoint-settings"))
    implementation(project(":provider:impl"))
    implementation(project(":provider:contract"))
    implementation(project(":repository:impl"))
    implementation(project(":ui:nav:impl"))
    implementation(project(":api"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.kotlinx.serialization.json)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    implementation(libs.timber)
    implementation(libs.retrofit.core)
    implementation(libs.retrofit.converter.kotlinx.serialization)

    testImplementation(libs.junit)
    testImplementation(libs.hilt.android.testing)
    kspTest(libs.hilt.compiler)
    testImplementation(libs.robolectric)

    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
