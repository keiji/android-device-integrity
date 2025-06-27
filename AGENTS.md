android以下はクライアントアプリ（Android）のソースコードです。
server以下はサーバー側のソースコードです。

# Android SDK Setup for Building and Testing (AI Agent Guide)

This document outlines the steps for AI coding agents to set up the Android SDK environment required to build and test applications located under the `android` directory.

## 1. Prerequisites

Before proceeding with the Android SDK setup, ensure the following are installed and configured:

*   **Java Development Kit (JDK):**
    *   **Project JDK Version:** A specific JDK version is required for compiling the project's Java/Kotlin source code. Please check the project's `build.gradle.kts` files (e.g., `android/app/build.gradle.kts`) for `sourceCompatibility` and `targetCompatibility` under `compileOptions`, or the `jvmTarget` in `kotlinOptions`. For this project, it is typically **JDK 11**.
    *   Ensure the `JAVA_HOME` environment variable is set correctly to this JDK installation path (e.g., JDK 11).
    *   Verify installation: `java -version`
    *   **Android Gradle Plugin (AGP) JDK Version:** The Android Gradle Plugin itself may require a newer JDK version to run (e.g., JDK 17). If you encounter errors like "Android Gradle plugin requires Java X to run", you will need to configure Gradle to use that specific JDK version for its daemon.
        *   Set `org.gradle.java.home=/path/to/jdk-X` (replace X with the required version, e.g., `/usr/lib/jvm/java-17-openjdk-amd64`) in the `android/gradle.properties` file.
        *   `JAVA_HOME` should still point to the project's compilation JDK (e.g., JDK 11).
    *   **SDK Manager JDK Version:** The `sdkmanager` tool itself might also require a newer JDK (e.g., JDK 17). If you see `UnsupportedClassVersionError` when running `sdkmanager`, temporarily set `JAVA_HOME` to JDK 17+ for `sdkmanager` execution, then revert it.

## 2. Android SDK Setup Instructions

Follow these steps precisely to set up the Android SDK.

1.  **Install Android SDK Command-line Tools:**
    *   The following commands will download and install the Android SDK command-line tools to `~/AndroidSdk`.
    ```bash
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip -O /tmp/tools.zip
    unzip -o /tmp/tools.zip -d /tmp/tools
    mkdir -p ~/AndroidSdk/cmdline-tools/latest
    mv -f /tmp/tools/cmdline-tools/* ~/AndroidSdk/cmdline-tools/latest
    rm -rf /tmp/tools
    rm /tmp/tools.zip
    ```

2.  **Configure Environment Variables:**
    *   Set these environment variables. For persistence, add them to your shell's configuration file (e.g., `~/.bashrc`, `~/.zshrc`) and reload your shell.
    ```bash
    export ANDROID_HOME="$HOME/AndroidSdk"
    export ANDROID_SDK_ROOT="$HOME/AndroidSdk" # ANDROID_HOME is preferred, but some older tools might use this.
    export PATH="$PATH:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin"
    export PATH="$PATH:$ANDROID_SDK_ROOT/platform-tools" # platform-tools will be installed in the next step.
    ```
    *   **Important for AI Agents:** After setting these, ensure your current shell session reflects these changes. If you are in a persistent environment, you might need to re-initialize your shell or source the configuration file (e.g., `source ~/.bashrc`).

3.  **Install SDK Packages:**
    *   Use the `sdkmanager` tool to install the necessary platform tools, platforms, and build tools. The versions specified below are known to work with this project.
    ```bash
    sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.1"
    ```
    *   **Note for AI Agents:**
        *   If you encounter issues with these specific versions (e.g., "Package ... not available"), it might indicate the versions need updating. Check the `android/app/build.gradle.kts` file for `compileSdk` (often defined in `libs.versions.toml`) and `buildToolsVersion` directives for the correct versions to install.
        *   `sdkmanager` might require a newer JDK (e.g., JDK 17) to run. If you encounter `UnsupportedClassVersionError`, temporarily switch your `JAVA_HOME` to JDK 17+ for this command and then switch back to the project's JDK (e.g., JDK 11).

4.  **Accept SDK Licenses:**
    *   Accept all SDK licenses by running:
    ```bash
    yes | sdkmanager --licenses
    ```
    *   **Note for AI Agents:** If this command fails, ensure `sdkmanager` is accessible (PATH configured correctly) and try running it without `yes |` to manually review and accept licenses if prompted.

5.  **Create `local.properties` for the Android Project:**
    *   This file tells the Android Gradle Plugin where to find the SDK.
    *   Create a file named `local.properties` in the `android` directory of your project with the following content:
    ```properties
    sdk.dir=/path/to/your/AndroidSdk
    ```
    *   You can create this file with the following command from the repository root. AI Agents should replace `$HOME` with the actual absolute path to their home directory (e.g., `/home/agent/AndroidSdk` or use `$(eval echo ~$USER)/AndroidSdk` if the shell supports it).
    ```bash
    # For AI Agents, resolve $HOME to an absolute path:
    echo "sdk.dir=$(eval echo ~$USER)/AndroidSdk" > android/local.properties
    # Alternatively, if $HOME is already correctly set for the agent's user:
    # echo "sdk.dir=\$HOME/AndroidSdk" > android/local.properties
    ```
    *   **Note for AI Agents:** Ensure this command is run from the *repository root*. Using an absolute path for `sdk.dir` is generally more robust. If you still see warnings like "SDK location not found" related to `local.properties` during the build, but the build succeeds, it's likely `ANDROID_HOME` environment variable is correctly pointing to the SDK.

## 3. Building the Project

*   **Gradle Wrapper:** This project uses the Gradle Wrapper (`./gradlew`). Always use this script for building, as it ensures the correct Gradle version is used.
*   **Navigate to the Android project directory:** All Gradle commands should be run from the `android` directory.
    ```bash
    cd android
    ```

*   **Common Build Commands:**
    *   **Clean the project:**
        ```bash
        ./gradlew clean
        ```
    *   **Build the debug APK (for testing and development):**
        ```bash
        ./gradlew assembleDebug
        ```
        *Output APK location: `app/build/outputs/apk/debug/app-debug.apk`*
    *   **Run unit tests:**
        ```bash
        ./gradlew testDebugUnitTest
        ```
    *   **Run Android Lint checks:**
        ```bash
        ./gradlew lintDebug
        ```
    *   **Full build (as originally specified):**
        ```bash
        ./gradlew build
        ```
        *This typically runs `assembleDebug`, `assembleRelease`, and associated tests. For quicker iteration, prefer `assembleDebug`.*

## 4. Troubleshooting Common Issues

*   **`SDK location not found. Define location with sdk.dir in the local.properties file or with an ANDROID_HOME environment variable.`**
    *   Ensure `android/local.properties` exists and `sdk.dir` points to the correct SDK path (e.g., `/home/agent/AndroidSdk`). Using an absolute path is recommended.
    *   Verify `ANDROID_HOME` environment variable is set correctly and exported in your current session. This is often the primary way Gradle finds the SDK.
*   **`java.lang.UnsupportedClassVersionError` or issues related to JDK version:**
    *   **During `sdkmanager` execution:** This tool might require a newer JDK (e.g., JDK 17+) than the project's compilation JDK. See Section 2.3 Note.
    *   **During Gradle build (`./gradlew`):**
        *   If the error message indicates "Android Gradle plugin requires Java X to run", set `org.gradle.java.home=/path/to/jdk-X` in `android/gradle.properties`. Ensure `JAVA_HOME` still points to the JDK version specified for project compilation (e.g., JDK 11). See Section 1 Prerequisites.
        *   If the error relates to source compilation, ensure `JAVA_HOME` points to the correct JDK version specified in `sourceCompatibility` / `jvmTarget` (e.g., JDK 11).
    *   Verify `java -version` and `javac -version` reflect the intended active JDK for the task at hand.
*   **`sdkmanager: command not found` or `aapt: command not found`:**
    *   The `PATH` environment variable is likely not configured correctly to include SDK tools. Refer to Section 2.2.
    *   Ensure you have reloaded your shell configuration or opened a new terminal after modifying environment variables.
*   **Gradle sync issues or "Could not resolve all files for configuration..."**:
    *   Ensure network connectivity if dependencies need to be downloaded.
    *   Try cleaning the build: `./gradlew clean`
    *   Try a build with stacktrace for more details: `./gradlew assembleDebug --stacktrace`
    *   If you are behind a proxy, configure Gradle proxy settings in `~/.gradle/gradle.properties`.
*   **License not accepted:**
    *   Re-run `yes | sdkmanager --licenses`. If it still fails, run `sdkmanager --licenses` interactively.

## 5. Notes for AI Agents

*   **Working Directory:** Most commands specific to Android (especially `./gradlew` commands) should be executed from within the `android` directory.
*   **Environment Variables:** Ensure `JAVA_HOME` and `ANDROID_HOME` (and additions to `PATH`) are correctly set and available in your execution environment *before* running any build commands.
*   **Build Failures:** If a build fails, carefully examine the error output. The messages usually provide clues. The "Troubleshooting" section above might also help.
*   **Idempotency:** The setup scripts for SDK tools are generally safe to re-run if you suspect an incomplete setup.
*   **Checking Project Configuration:** Key Android configuration files include:
    *   `android/build.gradle` (Project-level Gradle configuration)
    *   `android/app/build.gradle` (App-module Gradle configuration - check `compileSdk`, `minSdk`, `targetSdk`, `versionCode`, `versionName`, dependencies here)
    *   `android/app/src/main/AndroidManifest.xml` (App manifest - permissions, activities, services, etc.)
    *   `gradle/wrapper/gradle-wrapper.properties` (Specifies Gradle version)
