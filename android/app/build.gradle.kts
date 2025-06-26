plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
}

import java.io.File
import java.io.FileInputStream

// https://docs.gradle.org/8.2/userguide/configuration_cache.html#config_cache:requirements:external_processes
val commitHash = providers.exec {
    commandLine("git", "rev-parse", "--short", "HEAD")
}.standardOutput.asText.get().trim()

android {
    namespace = "dev.keiji.deviceintegrity"
    compileSdk = libs.versions.androidCompileSdk.get().toInt()

    signingConfigs {
        create("release") {
            val keystorePropertiesFile = rootProject.file("keystore.properties")
            if (keystorePropertiesFile.exists()) {
                val props = mutableMapOf<String, String>()
                keystorePropertiesFile.forEachLine { line ->
                    val parts = line.split("=", limit = 2)
                    if (parts.size == 2) {
                        props[parts[0].trim()] = parts[1].trim()
                    }
                }
                storeFile = props["storeFile"]?.let { file(it) }
                storePassword = props["storePassword"]
                keyAlias = props["keyAlias"]
                keyPassword = props["keyPassword"]
            } else {
                // Fallback to debug signing if keystore.properties is not found
                // This is useful for CI environments or developers who don't need to sign release builds
                println("Warning: keystore.properties not found. Using debug signing for release build.")
            }
        }
    }

    defaultConfig {
        applicationId = "dev.keiji.deviceintegrity"
        minSdk = libs.versions.androidMinSdk.get().toInt()
        targetSdk = libs.versions.androidTargetSdk.get().toInt()
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // TODO: Replace 0L with your actual Google Cloud Project Number
        buildConfigField("Long", "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", "0L")
        buildConfigField("String", "PLAY_INTEGRITY_BASE_URL", "\"https://playintegrity.googleapis.com/\"")
        buildConfigField("String", "KEY_ATTESTATION_BASE_URL", "\"https://keyattestation.googleapis.com/\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
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
    implementation(project(":ui:api-endpoint-settings"))
    implementation(project(":provider:impl"))
    api(project(":provider:contract")) // Changed to api
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
