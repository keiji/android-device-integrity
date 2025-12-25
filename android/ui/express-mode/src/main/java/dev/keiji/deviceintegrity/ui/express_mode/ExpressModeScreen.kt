package dev.keiji.deviceintegrity.ui.express_mode

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.activity.compose.BackHandler
import dev.keiji.deviceintegrity.ui.common.InfoItemContent
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExpressModeScreen(
    uiState: ExpressModeUiState,
    onCopyClick: () -> Unit = {},
    onShareClick: () -> Unit = {},
    onBack: () -> Unit = {},
    onExitApp: () -> Unit = {},
) {
    val scrollState = rememberScrollState()
    val showExitConfirmationDialog = remember { mutableStateOf(false) }

    fun handleBackOrClose() {
        if (uiState.isProgressVisible) {
            showExitConfirmationDialog.value = true
        } else {
            onBack()
        }
    }

    BackHandler {
        handleBackOrClose()
    }

    if (showExitConfirmationDialog.value) {
        AlertDialog(
            onDismissRequest = { showExitConfirmationDialog.value = false },
            title = {
                Text(text = stringResource(R.string.dialog_title_stop_verification))
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showExitConfirmationDialog.value = false
                        onExitApp()
                    }
                ) {
                    Text(text = stringResource(R.string.action_exit))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showExitConfirmationDialog.value = false
                    }
                ) {
                    Text(text = stringResource(R.string.action_continue_verification))
                }
            }
        )
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            CenterAlignedTopAppBar(
                title = { },
                navigationIcon = {
                    IconButton(onClick = { handleBackOrClose() }) {
                        Icon(
                            imageVector = Icons.Filled.Close,
                            contentDescription = "Close"
                        )
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(innerPadding)
                .padding(16.dp),
            horizontalAlignment = Alignment.Start
        ) {
            Text(
                text = stringResource(R.string.title_checking_integrity),
                style = MaterialTheme.typography.displaySmall
            )
            Spacer(modifier = Modifier.height(32.dp))
            val statusText = uiState.statusResId?.let { stringResource(it) } ?: ""
            Text(
                text = statusText,
            )
            Spacer(modifier = Modifier.height(16.dp))

            // HorizontalProgress
            if (uiState.isProgressVisible) {
                if (uiState.progress == -1) {
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth()
                    )
                } else {
                    val progress = if (uiState.maxProgress > 0) {
                        uiState.progress.toFloat() / uiState.maxProgress
                    } else {
                        0f
                    }
                    LinearProgressIndicator(
                        progress = { progress },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            if (uiState.playIntegrityInfoItems.isNotEmpty()) {
                InfoItemContent(
                    status = "Play Integrity",
                    isVerifiedSuccessfully = uiState.isPlayIntegritySuccess,
                    infoItems = uiState.playIntegrityInfoItems,
                    onCopyClick = onCopyClick,
                    onShareClick = onShareClick,
                    modifier = Modifier.fillMaxWidth()
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            if (uiState.keyAttestationInfoItems.isNotEmpty()) {
                InfoItemContent(
                    status = "Key Attestation",
                    isVerifiedSuccessfully = uiState.isKeyAttestationSuccess,
                    infoItems = uiState.keyAttestationInfoItems,
                    onCopyClick = onCopyClick,
                    onShareClick = onShareClick,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun ExpressModeScreenPreview() {
    DeviceIntegrityTheme {
        ExpressModeScreen(
            uiState = ExpressModeUiState(
                progress = 3,
                maxProgress = 5
            )
        )
    }
}

@Preview(showBackground = true)
@Composable
fun ExpressModeScreenResultPreview() {
    DeviceIntegrityTheme {
        ExpressModeScreen(
            uiState = ExpressModeUiState(
                progress = 5,
                maxProgress = 5,
                statusResId = R.string.status_complete,
                resultInfoItems = listOf(
                    dev.keiji.deviceintegrity.ui.common.InfoItem("Result", "Success"),
                    dev.keiji.deviceintegrity.ui.common.InfoItem("Details", "All checks passed")
                )
            )
        )
    }
}
