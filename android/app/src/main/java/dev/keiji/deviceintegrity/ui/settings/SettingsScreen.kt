package dev.keiji.deviceintegrity.ui.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Api
import androidx.compose.material.icons.filled.Article
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.keiji.deviceintegrity.BuildConfig
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel = viewModel(),
    onNavigateToOssLicenses: () -> Unit = {},
    onNavigateToApiSettings: () -> Unit = {},
    onNavigateToDeveloperInfo: () -> Unit = {},
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(vertical = 8.dp)
    ) {
        SettingsMenuItem(
            icon = Icons.Default.Info,
            title = "アプリのバージョン",
            subtitle = "${BuildConfig.VERSION_NAME} (${BuildConfig.BUILD_TYPE})",
            onClick = { /* No action for now */ }
        )
        SettingsMenuItem(
            icon = Icons.Default.Article,
            title = "開発元のURL",
            onClick = onNavigateToDeveloperInfo
        )
        SettingsMenuItem(
            icon = Icons.Default.Build,
            title = "オープンソースライセンス",
            onClick = onNavigateToOssLicenses
        )
        SettingsMenuItem(
            icon = Icons.Default.Api,
            title = "接続するAPI設定",
            onClick = onNavigateToApiSettings
        )
        // TODO: Display actual settings UI using uiState.sampleSetting if needed
    }
}

@Composable
fun SettingsMenuItem(
    icon: ImageVector,
    title: String,
    subtitle: String? = null,
    onClick: () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp) // Increased padding for height
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Start,
            modifier = Modifier.height(48.dp) // Increased height for menu item
        ) {
            Icon(
                imageVector = icon,
                contentDescription = title,
                modifier = Modifier.padding(end = 16.dp)
            )
            Column {
                Text(
                    text = title,
                    fontSize = 18.sp // Increased font size
                )
                if (subtitle != null) {
                    Text(
                        text = subtitle,
                        fontSize = 14.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun SettingsScreenPreview() {
    DeviceIntegrityTheme {
        SettingsScreen()
    }
}

@Preview(showBackground = true)
@Composable
fun SettingsMenuItemPreview() {
    DeviceIntegrityTheme {
        SettingsMenuItem(
            icon = Icons.Default.Info,
            title = "アプリのバージョン",
            subtitle = "1.0.0 (debug)",
            onClick = {}
        )
    }
}
