package dev.keiji.deviceintegrity.repository.contract

import java.security.KeyPair
import java.security.cert.X509Certificate

data class KeyPairData(
    val keyAlias: String,
    val certificates: Array<X509Certificate>,
    val keyPair: KeyPair? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KeyPairData

        if (keyAlias != other.keyAlias) return false
        if (!certificates.contentEquals(other.certificates)) return false
        if (keyPair != other.keyPair) return false

        return true
    }

    override fun hashCode(): Int {
        var result = keyAlias.hashCode()
        result = 31 * result + certificates.contentHashCode()
        result = 31 * result + (keyPair?.hashCode() ?: 0)
        return result
    }
}
