package dev.keiji.deviceintegrity.ui.nav.contract

sealed class AppScreen(
    val route: String,
) {
    object PlayIntegrity : AppScreen("play_integrity")
    object KeyAttestation : AppScreen("key_attestation")
    object Menu : AppScreen("menu")
}
