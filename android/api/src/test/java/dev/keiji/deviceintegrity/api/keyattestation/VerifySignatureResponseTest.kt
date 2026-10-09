package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VerifySignatureResponseTest {

    private val sampleJson = """
    {
        "is_verified": true,
        "session_id": "6c5f8a2c-1a3b-4d5e-8f7a-2b3c4d5e6f70",
        "attestation_info": {
            "attestation_security_level": 1,
            "attestation_version": 400,
            "keymint_security_level": 1,
            "keymint_version": 400,
            "attestation_challenge": "Y2hhbGxlbmdlX3N0cmluZw",
            "software_enforced_properties": {
                "digests": [4],
                "padding": [1],
                "attestation_application_id": {
                    "application_signatures": ["8483bb6c82661a529afe5cbd270fbcde864c93fda2005dc8321f8e1bb486991f"],
                    "attestation_application_id": "dev.keiji.deviceintegrity",
                    "attestation_application_version_code": 14
                }
            },
            "hardware_enforced_properties": {
                "purpose": [2, 3],
                "algorithm": 3,
                "key_size": 256,
                "digests": [4],
                "ec_curve": 1,
                "origin": 0,
                "root_of_trust": {
                    "device_locked": true,
                    "verified_boot_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "verified_boot_key": "0000000000000000000000000000000000000000000000000000000000000000",
                    "verified_boot_state": 0
                },
                "os_version": 160000,
                "os_patch_level": 20260305
            }
        },
        "device_info": {
            "brand": "google",
            "model": "Pixel 6a",
            "device": "bluejay",
            "product": "bluejay",
            "manufacturer": "Google",
            "hardware": "bluejay",
            "board": "bluejay",
            "bootloader": "bluejay-16.2-13291547",
            "version_release": "16",
            "sdk_int": 36,
            "fingerprint": "google/bluejay/bluejay:16/BP2A.250605.031.A2/13578606:user/release-keys",
            "security_patch": "2025-06-05"
        },
        "security_info": {
            "is_device_lock_enabled": true,
            "is_biometrics_enabled": true,
            "has_class3_authenticator": true,
            "has_strongbox": true
        },
        "certificate_chain": []
    }
    """.trimIndent()

    @Test
    fun `parseVerifySignatureResponse deserializes digests field`() {
        val json = Json { ignoreUnknownKeys = true }
        val response = json.decodeFromString<VerifySignatureResponse>(sampleJson)

        assertTrue(response.isVerified)
        assertEquals(400, response.attestationInfo.attestationVersion)

        val softwareEnforced = response.attestationInfo.softwareEnforcedProperties
        assertEquals(listOf(4), softwareEnforced.digest)

        val hardwareEnforced = response.attestationInfo.hardwareEnforcedProperties
        assertEquals(listOf(2, 3), hardwareEnforced.purpose)
        assertEquals(listOf(4), hardwareEnforced.digest)
        assertEquals(0, hardwareEnforced.rootOfTrust?.verifiedBootState)
        assertEquals(
            "dev.keiji.deviceintegrity",
            softwareEnforced.attestationApplicationId?.attestationApplicationId,
        )
    }
}
