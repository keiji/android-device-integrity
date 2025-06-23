plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
    alias(libs.plugins.protobuf) // Added for Protocol Buffers
}

android {
    namespace = "dev.keiji.deviceintegrity.repository.impl"
    compileSdk = libs.versions.androidCompileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.androidMinSdk.get().toInt()
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
    sourceSets {
        getByName("main") {
            proto {
                srcDir("src/main/proto")
            }
        }
    }
}

dependencies {
    api(project(":repository:contract"))
    api(project(":provider:contract")) // Changed to api

    // Play Integrity API
    implementation(libs.play.integrity)

    // Coroutines for async operations
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.play.services)

    // Hilt for Dependency Injection
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    // DataStore
    implementation(libs.androidx.datastore.core)
    implementation(libs.androidx.datastore.preferences) // While we use Proto DataStore, this is often a common base
    implementation(libs.protobuf.kotlin.lite)


    implementation(libs.timber)

    testImplementation(libs.junit)
    // Robolectric and other test dependencies if needed for this module specifically
    // For PreferencesRepositoryImplTest, Robolectric is used.
    // It's often better to have a separate test module or configure it if it's only for a few tests.
    // For now, assuming it's okay here or managed via AGP test options if not explicitly listed.
    // testImplementation(libs.robolectric) // Example if you add robolectric to toml
}

protobuf {
    protoc {
        artifact = libs.protobuf.protoc.get().toString() // Updated to use version catalog
    }
    generateProtoTasks {
        all().forEach { task ->
            task.builtins {
                java {
                    option("lite")
                }
                kotlin {
                    option("lite")
                }
            }
        }
    }
}
