package dev.keiji.deviceintegrity.ui.main

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import dev.keiji.deviceintegrity.ui.main.R

sealed class AppScreen(
    val route: String,
    @StringRes val label: Int,
    @param:DrawableRes val icon: Int
) {
    object PlayIntegrity : AppScreen("play_integrity", R.string.app_screen_play_integrity_label, R.drawable.ic_shield)
    object KeyAttestation : AppScreen("key_attestation", R.string.app_screen_key_attestation_label, R.drawable.key_vertical_24dp_000000_fill1_wght400_grad0_opsz24)
    object Menu : AppScreen("menu", R.string.app_screen_menu_label, R.drawable.ic_menu)
}
