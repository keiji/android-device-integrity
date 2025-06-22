plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ksp)
    // Removed Hilt plugin: alias(libs.plugins.hilt)
}

android {
    namespace = "dev.keiji.deviceintegrity.provider.contract"
    compileSdk = 36

    defaultConfig {
        minSdk = 23
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
    kotlinOptions {
        jvmTarget = "11"
    }
}

dependencies {
    implementation(libs.timber)
    api(libs.play.integrity) // Use api since the interface exposes types from this library
    implementation("javax.inject:javax.inject:1") // For @Qualifier
    // Removed Hilt compiler: ksp(libs.hilt.compiler)
}
