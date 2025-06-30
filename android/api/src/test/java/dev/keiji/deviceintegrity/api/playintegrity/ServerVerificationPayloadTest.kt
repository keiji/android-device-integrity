package dev.keiji.deviceintegrity.api.playintegrity

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerVerificationPayloadTest {

    private val sampleJson = """
    {
        "device_info": {
            "board": "bluejay",
            "bootloader": "bluejay-16.2-13291547",
            "brand": "google",
            "device": "bluejay",
            "fingerprint": "google/bluejay/bluejay:16/BP2A.250605.031.A2/13578606:user/release-keys",
            "hardware": "bluejay",
            "manufacturer": "Google",
            "model": "Pixel 6a",
            "product": "bluejay",
            "sdk_int": 36,
            "security_patch": "2025-06-05",
            "version_release": "16"
        },
        "play_integrity_response": {
            "tokenPayloadExternal": {
                "accountDetails": {
                    "appLicensingVerdict": "UNEVALUATED"
                },
                "appIntegrity": {
                    "appRecognitionVerdict": "UNRECOGNIZED_VERSION",
                    "certificateSha256Digest": [
                        "hIO7bIJmGlKa_ly9Jw-83oZMk_2iAF3IMh-OG7SGmR8"
                    ],
                    "packageName": "dev.keiji.deviceintegrity",
                    "versionCode": "4"
                },
                "deviceIntegrity": {
                    "deviceAttributes": {
                        "sdkVersion": 36
                    },
                    "deviceRecognitionVerdict": [
                        "MEETS_DEVICE_INTEGRITY"
                    ],
                    "recentDeviceActivity": {
                        "deviceActivityLevel": "UNEVALUATED"
                    }
                },
                "environmentDetails": {
                    "appAccessRiskVerdict": {},
                    "playProtectVerdict": "UNEVALUATED"
                },
                "requestDetails": {
                    "nonce": "YqMFcbaN7X_qc9X9xbaGafR7J2sF7pvW",
                    "requestPackageName": "dev.keiji.deviceintegrity",
                    "timestampMillis": "1751089185015"
                }
            }
        },
        "security_info": {
            "has_class3_authenticator": true,
            "has_strongbox": true,
            "is_biometrics_enabled": true,
            "is_device_lock_enabled": true
        }
    }
    """.trimIndent()

    @Test
    fun `parseServerVerificationPayload successfully parses valid JSON`() {
        val json = Json { ignoreUnknownKeys = true } // Instantiating Json parser
        val payload = json.decodeFromString<ServerVerificationPayload>(sampleJson)

        assertNotNull(payload)

        // DeviceInfo assertions
        assertEquals("bluejay", payload.deviceInfo.board)
        assertEquals("google", payload.deviceInfo.brand)
        assertEquals("Pixel 6a", payload.deviceInfo.model)
        assertEquals(36, payload.deviceInfo.sdkInt)

        // PlayIntegrityResponseWrapper and TokenPayloadExternal assertions
        assertNotNull(payload.playIntegrityResponse)
        val tokenPayload = payload.playIntegrityResponse.tokenPayloadExternal
        assertNotNull(tokenPayload)

        // AccountDetails
        assertEquals("UNEVALUATED", tokenPayload.accountDetails?.appLicensingVerdict)

        // AppIntegrity
        assertEquals("UNRECOGNIZED_VERSION", tokenPayload.appIntegrity?.appRecognitionVerdict)
        assertEquals("dev.keiji.deviceintegrity", tokenPayload.appIntegrity?.packageName)
        // Assuming versionCode is Long, if it's String in JSON, this might need adjustment or custom serializer
        // For now, assuming kotlinx.serialization handles "4" to 4L or that the actual JSON uses a number.
        // If it strictly remains a string and the type is Long, parsing will fail.
        // Let's test for the string value "4" if the type was String, or 4L if type is Long.
        // Based on prior decision, type is Long?, so we expect 4L.
        // kotlinx.serialization should convert "4" to 4L if the target is Long.
        assertEquals(4L, tokenPayload.appIntegrity?.versionCode)
        assertEquals(listOf("hIO7bIJmGlKa_ly9Jw-83oZMk_2iAF3IMh-OG7SGmR8"), tokenPayload.appIntegrity?.certificateSha256Digest)


        // DeviceIntegrity
        assertEquals(listOf("MEETS_DEVICE_INTEGRITY"), tokenPayload.deviceIntegrity?.deviceRecognitionVerdict)
        assertEquals(36, tokenPayload.deviceIntegrity?.deviceAttributes?.sdkVersion)
        assertEquals("UNEVALUATED", tokenPayload.deviceIntegrity?.recentDeviceActivity?.deviceActivityLevel)


        // EnvironmentDetails
        assertNotNull(tokenPayload.environmentDetails?.appAccessRiskVerdict) // Empty object
        assertEquals("UNEVALUATED", tokenPayload.environmentDetails?.playProtectVerdict)

        // RequestDetails
        assertEquals("YqMFcbaN7X_qc9X9xbaGafR7J2sF7pvW", tokenPayload.requestDetails?.nonce)
        assertEquals("dev.keiji.deviceintegrity", tokenPayload.requestDetails?.requestPackageName)
        // Similar to versionCode, assuming "1751089185015" is parsed to Long.
        assertEquals(1751089185015L, tokenPayload.requestDetails?.timestampMillis)

        // SecurityInfo assertions
        assertTrue(payload.securityInfo.hasClass3Authenticator)
        assertTrue(payload.securityInfo.hasStrongbox)
        assertTrue(payload.securityInfo.isBiometricsEnabled)
        assertTrue(payload.securityInfo.isDeviceLockEnabled)
    }
}
