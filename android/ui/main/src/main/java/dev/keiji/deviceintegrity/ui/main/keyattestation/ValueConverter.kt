package dev.keiji.deviceintegrity.ui.main.keyattestation

object ValueConverter {

    fun convertSecurityLevelToString(value: Int): String {
        return when (value) {
            0 -> "Software(0)"
            1 -> "TrustedEnvironment(1)"
            2 -> "StrongBox(2)"
            else -> value.toString()
        }
    }

    fun convertVerifiedBootStateToString(value: Int): String {
        return when (value) {
            0 -> "Verified(0)"
            1 -> "SelfSigned(1)"
            2 -> "Unverified(2)"
            3 -> "Failed(3)"
            else -> value.toString()
        }
    }

    fun convertAlgorithmToString(value: Int): String {
        return when (value) {
            1 -> "RSA(1)"
            3 -> "EC(3)"
            32 -> "AES(32)"
            33 -> "TripleDES(33)"
            128 -> "HMAC(128)"
            else -> value.toString()
        }
    }

    fun convertPurposeToString(value: Int): String {
        return when (value) {
            0 -> "ENCRYPT(0)"
            1 -> "DECRYPT(1)"
            2 -> "SIGN(2)"
            3 -> "VERIFY(3)"
            5 -> "WRAP_KEY(5)"
            else -> value.toString()
        }
    }

    fun convertOriginToString(value: Int): String {
        return when (value) {
            0 -> "GENERATED(0)"
            1 -> "DERIVED(1)"
            2 -> "IMPORTED(2)"
            else -> value.toString()
        }
    }
}
