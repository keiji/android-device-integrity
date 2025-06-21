package dev.keiji.deviceintegrity.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.graphics.vector.ImageVector

sealed class AppScreen(
    val route: String,
    val label: String,
    val icon: ImageVector
) {
    object PlayIntegrity : AppScreen("play_integrity", "Play Integrity", Icons.Filled.PlayCircle)
    object KeyAttestation : AppScreen("key_attestation", "Key Attestation", Icons.Filled.Key)
    object Settings : AppScreen("settings", "Settings", Icons.Filled.Settings)
}

val bottomNavigationItems = listOf(
    AppScreen.PlayIntegrity,
    AppScreen.KeyAttestation,
    AppScreen.Settings
)
