package dev.keiji.deviceintegrity.ui.express_mode

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.common.InfoItemContent
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ExpressModeResultScreen(
    uiState: ExpressModeUiState,
    onCopyClick: () -> Unit = {},
    onShareClick: () -> Unit = {},
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
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize(),
            contentPadding = innerPadding
        ) {
            stickyHeader {
                val tabs = listOf("Play Integrity", "Key Attestation")

                TabRow(
                    selectedTabIndex = selectedTabIndex,
                    modifier = Modifier.background(MaterialTheme.colorScheme.background)
                ) {
                    tabs.forEachIndexed { index, title ->
                        Tab(
                            selected = selectedTabIndex == index,
                            onClick = { selectedTabIndex = index },
                            text = { Text(text = title) }
                        )
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(16.dp))

                when (selectedTabIndex) {
                    0 -> {
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

                    1 -> {
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
