# Android SDK Setup for Building and Testing

This document outlines the steps to set up the Android SDK environment required to build and test applications located under the `android` directory.

## Setup Instructions

1.  **Install Android SDK:**
    Execute the following commands in your terminal to download and install the Android SDK command-line tools:
    ```bash
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip -O /tmp/tools.zip
    unzip /tmp/tools.zip -d /tmp/tools
    mkdir -p ~/AndroidSdk/cmdline-tools/latest
    mv /tmp/tools/cmdline-tools/* ~/AndroidSdk/cmdline-tools/latest
    rm -rf /tmp/tools
    rm /tmp/tools.zip
    ```

2.  **Configure Environment Variables:**
    Set the following environment variables. You might want to add these to your shell's configuration file (e.g., `~/.bashrc`, `~/.zshrc`) for persistence.
    ```bash
    export ANDROID_HOME="$HOME/AndroidSdk"
    export ANDROID_SDK_ROOT="$HOME/AndroidSdk"
    export PATH="$PATH:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin"
    export PATH="$PATH:$ANDROID_SDK_ROOT/platform-tools"
    ```

3.  **Install SDK Packages:**
    Use the `sdkmanager` tool to install the necessary platform tools, platforms, and build tools.
    ```bash
    sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.1"
    ```

4.  **Accept SDK Licenses:**
    Accept the SDK licenses by running:
    ```bash
    yes | sdkmanager --licenses
    ```

5.  **Create `local.properties` for the Android Project:**
    Create a file named `local.properties` in the `android` directory of your project with the following content, ensuring the path points to your Android SDK installation:
    ```properties
    sdk.dir=$HOME/AndroidSdk
    ```

    You can create this file with the following command from the repository root:
    ```bash
    echo "sdk.dir=\$HOME/AndroidSdk" > android/local.properties
    ```

## Building the Project

After completing the setup, you should be able to build the Android application. Navigate to the `android` directory and run the Gradle build command:

```bash
cd android
./gradlew build
```

**Note:** If you encounter build issues, ensure that all environment variables are correctly set and that the `sdk.dir` in `android/local.properties` points to the correct Android SDK location.
