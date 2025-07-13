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

    fun convertEcCurveToString(value: Int): String {
        return when (value) {
            0 -> "P_224(0)"
            1 -> "P_256(1)"
            2 -> "P_384(2)"
            3 -> "P_521(3)"
            else -> value.toString()
        }
    }

    fun convertPaddingToString(value: Int): String {
        return when (value) {
            1 -> "NONE(1)"
            2 -> "RSA_OAEP(2)"
            3 -> "RSA_PSS(3)"
            4 -> "RSA_PKCS1_1_5_ENCRYPT(4)"
            5 -> "RSA_PKCS1_1_5_SIGN(5)"
            64 -> "PKCS7(64)"
            else -> value.toString()
        }
    }

    fun convertDigestToString(value: Int): String {
        return when (value) {
            0 -> "NONE(0)"
            1 -> "MD5(1)"
            2 -> "SHA1(2)"
            3 -> "SHA2_224(3)"
            4 -> "SHA2_256(4)"
            5 -> "SHA2_384(5)"
            6 -> "SHA2_512(6)"
            else -> value.toString()
        }
    }
}
