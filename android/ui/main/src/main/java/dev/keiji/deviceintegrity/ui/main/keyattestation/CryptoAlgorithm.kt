package dev.keiji.deviceintegrity.ui.main.keyattestation

enum class CryptoAlgorithm(val value: String, val label: String) {
    EC("EC", "Elliptic Curve"),
    ECDH("ECDH", "Elliptic Curve Diffie-Hellman"),
    RSA("RSA", "RSA")
}
