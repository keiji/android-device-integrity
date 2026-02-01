import org.gradle.util.internal.GUtil
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
    alias(libs.plugins.license.generator)
}

val versionPropertiesFile = rootProject.file("version.properties")
val versionProps = if (versionPropertiesFile.exists()) {
    GUtil.loadProperties(versionPropertiesFile)
} else {
    println("Warning: version.properties not found. Using default version values.")
    Properties() // Empty Properties object
}

val serverEndpointPropertiesFile = rootProject.file("server-endpoint.properties")
val serverEndpointProps: Properties = if (serverEndpointPropertiesFile.exists()) {
    GUtil.loadProperties(serverEndpointPropertiesFile)
} else {
    println("Warning: server-endpoint.properties not found. Using default server-endpoint values.")
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
            val keystorePropertiesPath = providers.environmentVariable("KEYSTORE_PROPERTIES_PATH").orNull
            val keystorePropertiesFile = keystorePropertiesPath?.let { file(it) }

            if (keystorePropertiesFile?.exists() == true) {
                println("Info: Using keystore.properties from environment variable KEYSTORE_PROPERTIES_PATH.")
                val keystoreProperties = GUtil.loadProperties(keystorePropertiesFile)
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            } else {
                println("Error: No keystore.properties file found.")
            }
        }
    }

    defaultConfig {
        applicationId = "dev.keiji.deviceintegrity"
        minSdk = libs.versions.androidMinSdk.get().toInt()
        targetSdk = libs.versions.androidTargetSdk.get().toInt()
        versionCode = versionProps.getProperty("versionCode", "1").toInt()
        versionName = versionProps.getProperty("versionName", "1.0.0")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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

            buildConfigField(
                "Long",
                "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
                serverEndpointProps.getProperty("PRODUCT_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", "0L")
            )
            buildConfigField(
                "String",
                "PLAY_INTEGRITY_BASE_URL",
                "\"${
                    serverEndpointProps.getProperty(
                        "PRODUCT_PLAY_INTEGRITY_BASE_URL",
                        "https://playintegrity.googleapis.com/"
                    )
                }\""
            )
            buildConfigField(
                "String",
                "KEY_ATTESTATION_BASE_URL",
                "\"${
                    serverEndpointProps.getProperty(
                        "PRODUCT_KEY_ATTESTATION_BASE_URL",
                        "https://keyattestation.googleapis.com/"
                    )
                }\""
            )
        }
        create("develop") {
            initWith(getByName("release"))
            applicationIdSuffix = ".develop"
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            matchingFallbacks.add("debug")
            // proguardFiles are inherited from release.
            // versionNameSuffix is inherited from release.

            buildConfigField(
                "Long",
                "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
                serverEndpointProps.getProperty("DEVELOP_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", "0L")
            )
            buildConfigField(
                "String",
                "PLAY_INTEGRITY_BASE_URL",
                "\"${
                    serverEndpointProps.getProperty(
                        "DEVELOP_PLAY_INTEGRITY_BASE_URL",
                        "https://playintegrity.googleapis.com/"
                    )
                }\""
            )
            buildConfigField(
                "String",
                "KEY_ATTESTATION_BASE_URL",
                "\"${
                    serverEndpointProps.getProperty(
                        "DEVELOP_KEY_ATTESTATION_BASE_URL",
                        "https://keyattestation.googleapis.com/"
                    )
                }\""
            )
        }
        debug {
            applicationIdSuffix = ".develop"
            versionNameSuffix = "-$commitHash"

            buildConfigField(
                "Long",
                "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
                serverEndpointProps.getProperty("DEVELOP_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER", "0L")
            )
            buildConfigField(
                "String",
                "PLAY_INTEGRITY_BASE_URL",
                "\"${
                    serverEndpointProps.getProperty(
                        "DEVELOP_PLAY_INTEGRITY_BASE_URL",
                        "https://playintegrity.googleapis.com/"
                    )
                }\""
            )
            buildConfigField(
                "String",
                "KEY_ATTESTATION_BASE_URL",
                "\"${
                    serverEndpointProps.getProperty(
                        "DEVELOP_KEY_ATTESTATION_BASE_URL",
                        "https://keyattestation.googleapis.com/"
                    )
                }\""
            )
        }
    }
    compileOptions {
        isCoreLibraryDesugaringEnabled = true

        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    buildFeatures {
        buildConfig = true

    }

}

mavenLicenseGenerator {
    workingDir = rootProject.layout.buildDirectory.dir("maven-license-generator").get().asFile
    localRepositoryDirs = listOf(File(System.getProperty("user.home"), ".m2/repository"))
    repositoryUrls = listOf(
        "https://repo1.maven.org/maven2",
        "https://dl.google.com/android/maven2",
        "https://maven.repository.redhat.com/ga"
    )
    removeConflictingVersions = true
    ignoreScopes = listOf("test", "provided")
    includeDependencies = false
    includeSettings = false

    targets {
        create("main") {
            configurations = listOf("releaseRuntimeClasspath")
        }
    }

    outputSettings {
        create("complete") {
            path =
                rootProject.layout.projectDirectory.file("license_generator/licenses.json").asFile
            includeSettings = false
            prettyPrintEnabled = false
        }
        create("incomplete") {
            path =
                rootProject.layout.projectDirectory.file("license_generator/licenses-incomplete.json").asFile
            includeSettings = false
            prettyPrintEnabled = true
        }
    }
}

dependencies {
    implementation(project(":ui:agreement"))
    implementation(project(":ui:license"))
    implementation(project(":ui:express-mode"))
    implementation(project(":provider:impl"))
    implementation(project(":provider:contract"))
    implementation(project(":crypto:contract"))
    implementation(project(":crypto:impl"))
    implementation(project(":repository:impl"))
    implementation(project(":ui:nav:impl"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.kotlinx.serialization.json)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    ksp(libs.kotlin.metadata.jvm)

    implementation(libs.timber)
    implementation(libs.retrofit.core)
    implementation(libs.retrofit.converter.kotlinx.serialization)
    implementation(libs.okhttp)
    implementation(libs.okhttp.logging.interceptor)

    coreLibraryDesugaring(libs.desugar.jdk.libs)

    testImplementation(libs.junit)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.hilt.android.testing)
    kspTest(libs.hilt.compiler)
    testImplementation(libs.robolectric)

    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
