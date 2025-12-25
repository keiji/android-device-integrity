package dev.keiji.deviceintegrity.ui.menu

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
import androidx.compose.ui.res.stringResource
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
            title = stringResource(id = R.string.settings_title_app_version),
            subtitle = uiState.appVersionName,
        )
        SettingsMenuItem(
            title = stringResource(id = R.string.settings_title_device_name),
            subtitle = uiState.deviceName,
        )
        SettingsMenuItem(
            title = stringResource(id = R.string.settings_title_os_version),
            subtitle = uiState.osVersion,
        )
        SettingsMenuItem(
            title = stringResource(id = R.string.settings_title_security_patch),
            subtitle = uiState.securityPatchLevel,
        )
        SettingsMenuItem(
            title = stringResource(id = R.string.settings_title_privacy_policy),
            onClick = onNavigateToPrivacyPolicy
        )
        SettingsMenuItem(
            title = stringResource(id = R.string.settings_title_oss_licenses),
            onClick = onNavigateToOssLicenses
        )
        SettingsMenuItem(
            title = stringResource(id = R.string.settings_title_support_site),
            onClick = onNavigateToDeveloperInfo
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
                .defaultMinSize(minHeight = 64.dp)
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
