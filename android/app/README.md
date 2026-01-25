# Android App

This is the main application module for the Device Integrity project.

## Building the Application

### Creating App Bundles

This project supports different build variants for creating app bundles:

*   `bundleDevelop`: This variant is intended for development and staging environments. It connects to the development server endpoints.
*   `bundleRelease`: This is the production variant. It connects to the production servers and is intended for public release.

To build these bundles, use the following commands from the `android` directory:

*   **For the development bundle:**
    ```bash
    ./gradlew :app:bundleDevelop
    ```
*   **For the production bundle:**
    ```bash
    ./gradlew :app:bundleRelease
    ```

### Signing Configuration for Release Builds

To create a release build (including `bundleRelease`), you must provide a signing configuration via a `keystore.properties` file. The path to this file must be specified using the `KEYSTORE_PROPERTIES_PATH` environment variable.

**1. Create a `keystore.properties` file:**
   This file should contain the following properties:

   ```properties
   storeFile=/path/to/your/keystore.jks
   storePassword=your_store_password
   keyAlias=your_key_alias
   keyPassword=your_key_password
   ```

**2. Set the Environment Variable:**
   Before running the build command, set the `KEYSTORE_PROPERTIES_PATH` environment variable to the absolute path of your `keystore.properties` file.

   ```bash
   export KEYSTORE_PROPERTIES_PATH=/path/to/your/keystore.properties \
      ./gradlew :app:bundleRelease
   ```
