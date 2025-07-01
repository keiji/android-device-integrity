package dev.keiji.deviceintegrity.ui.main

import androidx.annotation.DrawableRes

sealed class AppScreen(
    val route: String,
    val label: String,
    @param:DrawableRes val icon: Int
) {
    object PlayIntegrity : AppScreen("play_integrity", "Play Integrity", R.drawable.ic_shield)
    object KeyAttestation : AppScreen("key_attestation", "Key Attestation", R.drawable.ic_key)
    object Menu : AppScreen("menu", "Menu", R.drawable.ic_menu)
}

val bottomNavigationItems = listOf(
    AppScreen.PlayIntegrity,
    // AppScreen.KeyAttestation,
    AppScreen.Menu
)
