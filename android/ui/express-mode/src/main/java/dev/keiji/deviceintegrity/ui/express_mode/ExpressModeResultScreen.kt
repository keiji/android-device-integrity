package dev.keiji.deviceintegrity.ui.express_mode

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.keiji.deviceintegrity.ui.common.InfoItemContent
import dev.keiji.deviceintegrity.ui.menu.SettingsScreen
import dev.keiji.deviceintegrity.ui.menu.SettingsUiEvent
import dev.keiji.deviceintegrity.ui.menu.SettingsViewModel
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

private sealed class ExpressModeTab(
    @StringRes val labelResId: Int,
    val icon: ImageVector,
    val description: String
) {
    data object PlayIntegrity : ExpressModeTab(
        R.string.result_screen_tab_play_integrity,
        Icons.Filled.Security,
        "Play Integrity"
    )

    data object KeyAttestation : ExpressModeTab(
        R.string.result_screen_tab_key_attestation,
        Icons.Filled.VpnKey,
        "Key Attestation"
    )

    data object Menu : ExpressModeTab(
        R.string.result_screen_tab_menu,
        Icons.Filled.Menu,
        "Menu"
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExpressModeResultScreen(
    uiState: ExpressModeUiState,
    onCopyClick: () -> Unit = {},
    onShareClick: () -> Unit = {},
    onNavigateToOssLicenses: () -> Unit = {},
    onExitApp: () -> Unit = {},
) {
    var selectedTab by remember { mutableStateOf<ExpressModeTab>(ExpressModeTab.PlayIntegrity) }
    val tabs = listOf(
        ExpressModeTab.PlayIntegrity,
        ExpressModeTab.KeyAttestation,
        ExpressModeTab.Menu
    )

    BackHandler {
        onExitApp()
    }

    Scaffold(
        modifier = Modifier
            .fillMaxSize(),
        bottomBar = {
            NavigationBar {
                tabs.forEach { tab ->
                    NavigationBarItem(
                        selected = selectedTab == tab,
                        onClick = { selectedTab = tab },
                        icon = {
                            Icon(
                                imageVector = tab.icon,
                                contentDescription = tab.description
                            )
                        },
                        label = { Text(stringResource(id = tab.labelResId)) }
                    )
                }
            }
        }
    ) { innerPadding ->
        when (selectedTab) {
            ExpressModeTab.PlayIntegrity -> {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize(),
                    contentPadding = innerPadding
                ) {
                    item {
                        if (uiState.playIntegrityInfoItems.isNotEmpty()) {
                            InfoItemContent(
                                status = stringResource(id = R.string.result_screen_tab_play_integrity),
                                isVerifiedSuccessfully = uiState.isPlayIntegritySuccess,
                                infoItems = uiState.playIntegrityInfoItems,
                                showStatus = false,
                                onCopyClick = onCopyClick,
                                onShareClick = onShareClick,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp)
                            )
                        }
                    }
                }
            }

            ExpressModeTab.KeyAttestation -> {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize(),
                    contentPadding = innerPadding
                ) {
                    item {
                        if (uiState.keyAttestationInfoItems.isNotEmpty()) {
                            InfoItemContent(
                                status = stringResource(id = R.string.result_screen_tab_key_attestation),
                                isVerifiedSuccessfully = uiState.isKeyAttestationSuccess,
                                infoItems = uiState.keyAttestationInfoItems,
                                showStatus = false,
                                onCopyClick = onCopyClick,
                                onShareClick = onShareClick,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp)
                            )
                        }
                    }
                }
            }

            ExpressModeTab.Menu -> {
                // Menu (Settings)
                val viewModel: SettingsViewModel = hiltViewModel()
                val settingsUiState by viewModel.uiState.collectAsStateWithLifecycle()
                val context = LocalContext.current

                LaunchedEffect(viewModel.eventFlow) {
                    viewModel.eventFlow.collect { event ->
                        when (event) {
                            is SettingsUiEvent.OpenUrl -> {
                                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(event.url))
                                context.startActivity(intent)
                            }
                        }
                    }
                }

                SettingsScreen(
                    modifier = Modifier.padding(innerPadding),
                    uiState = settingsUiState,
                    onNavigateToOssLicenses = onNavigateToOssLicenses,
                    onNavigateToDeveloperInfo = { viewModel.openSupportSiteUrl() },
                    onNavigateToPrivacyPolicy = { viewModel.openPrivacyPolicyUrl() }
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun ExpressModeResultScreenPreview() {
    DeviceIntegrityTheme {
        ExpressModeResultScreen(
            uiState = ExpressModeUiState(
                playIntegrityInfoItems = listOf(
                    dev.keiji.deviceintegrity.ui.common.InfoItem("Result", "Success")
                ),
                keyAttestationInfoItems = listOf(
                    dev.keiji.deviceintegrity.ui.common.InfoItem("Result", "Success")
                )
            )
        )
    }
}
