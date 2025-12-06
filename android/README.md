# Android Client for Device Integrity

This directory contains the Android client application for the Device Integrity project. The app demonstrates how to interact with the backend services to perform device integrity checks using Key Attestation and the Play Integrity API.

## Project Structure

The Android project is organized into several modules:

-   `app`: The main application module that integrates all other modules.
-   `api`: Defines the data models and API interfaces for communicating with the backend server.
-   `crypto`: Contains cryptography-related logic, including key generation and management.
-   `provider`: Implements data providers for accessing device and application information.
-   `repository`: Manages data operations, abstracting data sources from the UI.
-   `ui`: Contains all UI-related components, including activities, fragments, and view models.

## Building the Application

### Prerequisites

-   Android Studio (latest stable version recommended)
-   Android SDK (see `android/AGENTS.md` for setup instructions)
-   Java Development Kit (JDK) 11 or higher

### Build from Command Line

Navigate to the `android` directory and use the Gradle wrapper to build the app.

-   **Clean the project:**
    ```bash
    ./gradlew clean
    ```
-   **Build a debug APK:**
    ```bash
    ./gradlew assembleDebug
    ```
    The output APK will be located in `app/build/outputs/apk/debug/`.

-   **Run unit tests:**
    ```bash
    ./gradlew testDebugUnitTest
    ```

### Build with Android Studio

1.  Open Android Studio.
2.  Select "Open an existing Android Studio project".
3.  Navigate to and select the `android` directory within this repository.
4.  Let Android Studio sync the project with Gradle.
5.  Use the "Build" menu to build the project or the "Run" menu to deploy it to a device or emulator.

## Configuration

The application requires configuration to communicate with the backend server.

### Server Endpoint

The server's base URL needs to be configured. This is typically done in a properties file or as a build-time variable. Refer to `server-endpoint-sample.properties` for an example.

### Play Integrity

To use the Play Integrity API, you need to:

1.  Link your app to a Google Cloud project.
2.  Enable the Play Integrity API in your Google Cloud Console.
3.  Ensure your app's package name and signing certificate hash are correctly configured in your Cloud project.

## Development

-   **Code Style**: The project follows the standard Kotlin coding conventions.
-   **Dependencies**: Dependencies are managed using Gradle and are defined in the `build.gradle.kts` files for each module and in the `gradle/libs.versions.toml` file.
-   **AI Agent Instructions**: For AI software engineers, detailed instructions on environment setup, building, and troubleshooting are available in `android/AGENTS.md`. It is crucial to follow these instructions to ensure a consistent development environment.

## License Generation

Run the following command to regenerate the open-source software license files (`licenses.json` and `licenses-incomplete.json`). These files are used to display license information within the application.

```bash
./gradlew generateLicense
```
