package dev.keiji.deviceintegrity.ui.main

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import dev.keiji.deviceintegrity.ui.nav.contract.AppScreen
import dev.keiji.deviceintegrity.ui.playintegrity.R as PlayIntegrityR

data class BottomNavigationItem(
    val screen: AppScreen,
    @StringRes val label: Int,
    @DrawableRes val icon: Int,
)

fun AppScreen.toBottomNavigationItem(): BottomNavigationItem {
    return when (this) {
        AppScreen.PlayIntegrity -> BottomNavigationItem(
            this,
            PlayIntegrityR.string.app_screen_play_integrity_label,
            PlayIntegrityR.drawable.ic_shield
        )

        AppScreen.KeyAttestation -> BottomNavigationItem(
            this,
            R.string.app_screen_key_attestation_label,
            R.drawable.key_vertical_24dp_000000_fill1_wght400_grad0_opsz24
        )

        AppScreen.Menu -> BottomNavigationItem(
            this,
            R.string.app_screen_menu_label,
            R.drawable.ic_menu
        )
    }
}
