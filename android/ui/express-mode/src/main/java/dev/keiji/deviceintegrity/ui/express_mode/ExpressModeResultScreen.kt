package dev.keiji.deviceintegrity.ui.express_mode

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.keiji.deviceintegrity.ui.common.InfoItemContent
import dev.keiji.deviceintegrity.ui.menu.SettingsScreen
import dev.keiji.deviceintegrity.ui.menu.SettingsUiEvent
import dev.keiji.deviceintegrity.ui.menu.SettingsViewModel
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExpressModeResultScreen(
    uiState: ExpressModeUiState,
    onCopyClick: () -> Unit = {},
    onShareClick: () -> Unit = {},
    onNavigateToOssLicenses: () -> Unit = {},
    onExitApp: () -> Unit = {},
) {
    var selectedTabIndex by remember { mutableStateOf(0) }
    val scrollBehavior = TopAppBarDefaults.enterAlwaysScrollBehavior()

    BackHandler {
        onExitApp()
    }

    Scaffold(
        modifier = Modifier
            .fillMaxSize()
            .nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            CenterAlignedTopAppBar(
                title = { },
                navigationIcon = {
                    IconButton(onClick = { onExitApp() }) {
                        Icon(
                            imageVector = Icons.Filled.Close,
                            contentDescription = "Close"
                        )
                    }
                },
                scrollBehavior = scrollBehavior
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = selectedTabIndex == 0,
                    onClick = { selectedTabIndex = 0 },
                    icon = {
                        Icon(
                            imageVector = Icons.Filled.Security,
                            contentDescription = "Play Integrity"
                        )
                    },
                    label = { Text("Play Integrity") }
                )
                NavigationBarItem(
                    selected = selectedTabIndex == 1,
                    onClick = { selectedTabIndex = 1 },
                    icon = {
                        Icon(
                            imageVector = Icons.Filled.VpnKey,
                            contentDescription = "Key Attestation"
                        )
                    },
                    label = { Text("Key Attestation") }
                )
                NavigationBarItem(
                    selected = selectedTabIndex == 2,
                    onClick = { selectedTabIndex = 2 },
                    icon = {
                        Icon(
                            imageVector = Icons.Filled.Menu,
                            contentDescription = "Menu"
                        )
                    },
                    label = { Text("Menu") }
                )
            }
        }
    ) { innerPadding ->
        when (selectedTabIndex) {
            0 -> {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize(),
                    contentPadding = innerPadding
                ) {
                    item {
                        if (uiState.playIntegrityInfoItems.isNotEmpty()) {
                            InfoItemContent(
                                status = "Play Integrity",
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

            1 -> {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize(),
                    contentPadding = innerPadding
                ) {
                    item {
                        if (uiState.keyAttestationInfoItems.isNotEmpty()) {
                            InfoItemContent(
                                status = "Key Attestation",
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

            2 -> {
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
