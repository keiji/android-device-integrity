package dev.keiji.deviceintegrity.ui.main.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
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

@Composable
fun SettingsScreen(
    uiState: SettingsUiState,
    onNavigateToOssLicenses: () -> Unit = {},
    onNavigateToApiSettings: () -> Unit = {},
    onNavigateToDeveloperInfo: () -> Unit = {},
    onNavigateToTermsOfService: () -> Unit = {},
    onNavigateToPrivacyPolicy: () -> Unit = {},
) {
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(vertical = 8.dp)
    ) {
        SettingsMenuItem(
            title = "アプリのバージョン",
            subtitle = uiState.appVersionName,
        )
        SettingsMenuItem(
            title = "端末名",
            subtitle = uiState.deviceName,
        )
        SettingsMenuItem(
            title = "OSバージョン",
            subtitle = uiState.osVersion,
        )
        SettingsMenuItem(
            title = "セキュリティパッチ",
            subtitle = uiState.securityPatchLevel,
        )
        SettingsMenuItem(
            title = "アプリについて",
            onClick = onNavigateToDeveloperInfo
        )
        SettingsMenuItem(
            title = "利用規約",
            onClick = onNavigateToTermsOfService
        )
        SettingsMenuItem(
            title = "プライバシーポリシー",
            onClick = onNavigateToPrivacyPolicy
        )
        SettingsMenuItem(
            icon = Icons.Default.Build,
            title = "オープンソースライセンス",
            onClick = onNavigateToOssLicenses
        )
        SettingsMenuItem(
            title = "接続するAPI設定",
            onClick = onNavigateToApiSettings
        )
    }
}

@Composable
fun SettingsMenuItem(
    icon: ImageVector? = null,
    title: String,
    subtitle: String? = null,
    onClick: (() -> Unit)? = null
) {
    val clickableModifier = if (onClick != null) {
        Modifier.clickable(onClick = onClick)
    } else {
        Modifier
    }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .then(clickableModifier)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Start,
            modifier = Modifier
                .defaultMinSize(minHeight = 48.dp)
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = title,
                    modifier = Modifier.padding(end = 16.dp)
                )
            }
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
fun SettingsMenuItemPreview() {
    SettingsMenuItem(
        icon = Icons.Default.Info,
        title = "アプリのバージョン",
        subtitle = "1.0.0 (debug)",
    )
}

@Preview(showBackground = true)
@Composable
fun SettingsMenuItemClickablePreview() {
    SettingsMenuItem(
        icon = Icons.Default.Info,
        title = "アプリのバージョン",
        subtitle = "1.0.0 (debug)",
        onClick = {},
    )
}

@Preview(showBackground = true)
@Composable
fun SettingsScreenPreview() {
    SettingsScreen(
        uiState = SettingsUiState(
            appVersionName = "1.0.0-preview",
            appVersionCode = 10000,
            osVersion = "13 (Preview)",
            securityPatchLevel = "2023-03-05"
        ),
        onNavigateToOssLicenses = {},
        onNavigateToApiSettings = {},
        onNavigateToDeveloperInfo = {},
        onNavigateToTermsOfService = {},
        onNavigateToPrivacyPolicy = {}
    )
}
