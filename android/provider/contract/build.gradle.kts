plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
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
        sourceCompatibility = JavaVersion.VERSION_11 // appモジュールに合わせる
        targetCompatibility = JavaVersion.VERSION_11 // appモジュールに合わせる
    }
    kotlinOptions {
        jvmTarget = "11" // appモジュールに合わせる
    }
}

dependencies {
    implementation(libs.timber)
}
