package dev.keiji.deviceintegrity.ui.main

import androidx.annotation.DrawableRes

sealed class AppScreen(
    val route: String,
    val label: String,
    @param:DrawableRes val icon: Int
) {
    object PlayIntegrity : AppScreen("play_integrity", "Play Integrity", R.drawable.ic_play_circle)
    object KeyAttestation : AppScreen("key_attestation", "Key Attestation", R.drawable.ic_key)
    object Settings : AppScreen("settings", "Settings", R.drawable.ic_settings)
}

val bottomNavigationItems = listOf(
    AppScreen.PlayIntegrity,
    // AppScreen.KeyAttestation,
    AppScreen.Settings
)
