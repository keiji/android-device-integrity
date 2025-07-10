package dev.keiji.deviceintegrity.ui.main.keyattestation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.main.InfoItem
import dev.keiji.deviceintegrity.ui.main.InfoItemContent
import dev.keiji.deviceintegrity.ui.main.playintegrity.PlayIntegrityProgressConstants
import dev.keiji.deviceintegrity.ui.theme.ButtonHeight

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyAttestationScreen(
    uiState: KeyAttestationUiState, // uiState collected and passed from MainActivity
    onSelectedKeyTypeChange: (CryptoAlgorithm) -> Unit,
    onFetchNonceChallenge: () -> Unit,
    onGenerateKeyPair: () -> Unit,
    onRequestVerifyKeyAttestation: () -> Unit,
    onClickCopy: () -> Unit,
    onClickShare: () -> Unit
) {
    val scrollState = rememberScrollState()
    var keyTypeExpanded by remember { mutableStateOf(false) }
    val keyTypes = CryptoAlgorithm.values().toList()

    val isHorizontalProgressVisible = uiState.progressValue > PlayIntegrityProgressConstants.NO_PROGRESS && uiState.progressValue < PlayIntegrityProgressConstants.FULL_PROGRESS

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(top = 16.dp, start = 16.dp, end = 16.dp), // Adjusted padding for InfoItemContent
        horizontalAlignment = Alignment.Start,
        verticalArrangement = Arrangement.Top
    ) {
        Text(text = "Step1. サーバーからNonce/Challengeを取得")
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = onFetchNonceChallenge,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight),
            enabled = uiState.isStep1FetchNonceChallengeEnabled
        ) {
            Text(text = "Fetch Nonce/Challenge")
        }

        Spacer(modifier = Modifier.height(8.dp))
        if (uiState.isNonceVisible) {
            Text(text = "Nonce: ${uiState.nonce}")
        }
        Spacer(modifier = Modifier.height(8.dp))
        if (uiState.isChallengeVisible) {
            Text(text = "Challenge: ${uiState.challenge}")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(text = "Step 2. 鍵のアルゴリズムを設定")
        Spacer(modifier = Modifier.height(8.dp))

        Box(modifier = Modifier.fillMaxWidth()) {
            ExposedDropdownMenuBox(
                expanded = keyTypeExpanded,
                onExpandedChange = {
                    if (uiState.isStep2KeySelectionEnabled) { // isStep2KeySelectionEnabled already considers isLoading
                        keyTypeExpanded = !keyTypeExpanded
                    }
                }
            ) {
                TextField(
                    value = uiState.selectedKeyType.label,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Key Algorithm") },
                    trailingIcon = {
                        ExposedDropdownMenuDefaults.TrailingIcon(expanded = keyTypeExpanded)
                    },
                    colors = ExposedDropdownMenuDefaults.textFieldColors(),
                    modifier = Modifier
                        .menuAnchor()
                        .fillMaxWidth(),
                    enabled = uiState.isStep2KeySelectionEnabled
                )
                ExposedDropdownMenu(
                    expanded = keyTypeExpanded,
                    onDismissRequest = { keyTypeExpanded = false }
                ) {
                    keyTypes.forEach { algorithm ->
                        DropdownMenuItem(
                            text = { Text(algorithm.label) },
                            onClick = {
                                onSelectedKeyTypeChange(algorithm)
                                keyTypeExpanded = false
                            },
                            enabled = uiState.isStep2KeySelectionEnabled &&
                                    !(algorithm == CryptoAlgorithm.ECDH && !uiState.isEcdhAvailable)
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(text = "Step3. キーペア（構成証明付き）を生成")
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = onGenerateKeyPair,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight),
            enabled = uiState.isStep3GenerateKeyPairEnabled
        ) {
            Text(text = "Generate KeyPair")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(text = "Step4. キーペアと構成証明を検証")
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = onRequestVerifyKeyAttestation,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight),
            enabled = uiState.isStep4VerifyAttestationEnabled
        ) {
            Text(text = "Request Verify KeyAttestation")
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Progress Indicator
        if (isHorizontalProgressVisible) {
            LinearProgressIndicator(
                progress = uiState.progressValue,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
        }

        if (uiState.progressValue == PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp))
            }
            Spacer(modifier = Modifier.height(8.dp))
        }

        InfoItemContent(
            status = uiState.status,
            isVerifiedSuccessfully = uiState.infoItems.isNotEmpty() &&
                    (uiState.status.contains("Verification successful", ignoreCase = true) ||
                            // Add other conditions that signify success if necessary
                            uiState.infoItems.any { it.label.equals("Is Verified", ignoreCase = true) && it.value.equals("true", ignoreCase = true) }),
            infoItems = uiState.infoItems,
            onCopyClick = onClickCopy,
            onShareClick = onClickShare,
            modifier = Modifier.fillMaxWidth() // Ensure InfoItemContent takes available width
        )
        Spacer(modifier = Modifier.height(16.dp)) // Add padding at the bottom
    }
}

@Preview
@Composable
private fun KeyAttestationScreenPreview() {
    val previewItems = listOf(
        InfoItem("Session ID", "preview-session-id"),
        InfoItem("Is Verified", "true"),
        InfoItem("Attestation Version", "4"),
        InfoItem("Attestation Security Level", "1"),
        InfoItem("KeyMint Version", "1"),
        InfoItem("KeyMint Security Level", "1"),
        InfoItem("Attestation Challenge", "PREVIEW_ATTESTATION_CHALLENGE_XYZ123"),
        InfoItem("Software Enforced Properties", "", isHeader = true),
        InfoItem("Attestation Application ID", "", indentLevel = 1, isHeader = true),
        InfoItem("Application ID", "com.example.preview", indentLevel = 2),
        InfoItem("Version Code", "101", indentLevel = 2),
        InfoItem("Signature", "aabbccddeeff...", indentLevel = 2),
        InfoItem("Creation Datetime", "2023-01-01T10:00:00.000Z", indentLevel = 1),
        InfoItem("Algorithm", "1", indentLevel = 1),
        InfoItem("TEE Enforced Properties", "", isHeader = true),
        InfoItem("Origin", "0", indentLevel = 1),

        // Sample Device Info
        InfoItem("Device Info", "", isHeader = true, indentLevel = 0),
        InfoItem("Brand", "Google", indentLevel = 1),
        InfoItem("Model", "Pixel Preview", indentLevel = 1),
        InfoItem("SDK Int", "33", indentLevel = 1),

        // Sample Security Info
        InfoItem("Security Info", "", isHeader = true, indentLevel = 0),
        InfoItem("Is Device Lock Enabled", "true", indentLevel = 1),
        InfoItem("Has Strongbox", "true", indentLevel = 1),
    )
    KeyAttestationScreen(
        uiState = KeyAttestationUiState(
            nonce = "PREVIEW_NONCE_67890",
            challenge = "PREVIEW_CHALLENGE_ABCDE",
            selectedKeyType = CryptoAlgorithm.RSA,
            status = "Verification successful.",
            infoItems = previewItems
        ),
        onSelectedKeyTypeChange = { System.out.println("Preview: Key type changed to ${it.label}") },
        onFetchNonceChallenge = { System.out.println("Preview: Fetch Nonce/Challenge clicked") },
        onGenerateKeyPair = { System.out.println("Preview: Generate KeyPair clicked") },
        onRequestVerifyKeyAttestation = { System.out.println("Preview: Request Verify KeyAttestation clicked") },
        onClickCopy = { System.out.println("Preview: onClickCopy called") },
        onClickShare = { System.out.println("Preview: onClickShare called") }
    )
}
