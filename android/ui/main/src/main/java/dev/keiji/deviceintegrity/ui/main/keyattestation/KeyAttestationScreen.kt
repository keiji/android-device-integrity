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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.theme.ButtonHeight
import dev.keiji.deviceintegrity.ui.main.R

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

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp),
        horizontalAlignment = Alignment.Start,
        verticalArrangement = Arrangement.Top
    ) {
        Text(text = "Step1. サーバーからNonce/Challengeを取得")
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = onFetchNonceChallenge,
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight)
        ) {
            Text(text = "Fetch Nonce/Challenge")
        }

        Spacer(modifier = Modifier.height(8.dp))
        if (uiState.nonce.isNotEmpty()) {
            Text(text = "Nonce: ${uiState.nonce}")
        }
        Spacer(modifier = Modifier.height(8.dp))
        if (uiState.challenge.isNotEmpty()) {
            Text(text = "Challenge: ${uiState.challenge}")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(text = "Step2. 生成するキーペアの種類を設定")
        Spacer(modifier = Modifier.height(8.dp))

        val step2Enabled = uiState.nonce.isNotEmpty() && uiState.challenge.isNotEmpty()

        Box(modifier = Modifier.fillMaxWidth()) {
            ExposedDropdownMenuBox(
                expanded = keyTypeExpanded,
                onExpandedChange = { if (step2Enabled) keyTypeExpanded = !keyTypeExpanded }
            ) {
                TextField(
                    value = uiState.selectedKeyType.label,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Key Pair Type") },
                    trailingIcon = {
                        ExposedDropdownMenuDefaults.TrailingIcon(expanded = keyTypeExpanded)
                    },
                    colors = ExposedDropdownMenuDefaults.textFieldColors(),
                    modifier = Modifier
                        .menuAnchor()
                        .fillMaxWidth(),
                    enabled = step2Enabled
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
                            enabled = step2Enabled
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
            enabled = step2Enabled // Step 3 button enabled state depends on Step 2 being enabled
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
            enabled = uiState.generatedKeyPairData != null // Step 4 button enabled if key pair is generated
        ) {
            Text(text = "Request Verify KeyAttestation")
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Display general status
        if (uiState.status.isNotEmpty()) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = uiState.status,
                    style = if (uiState.verificationResultItems.isNotEmpty() && uiState.status.contains("successful", ignoreCase = true))
                                MaterialTheme.typography.titleMedium
                            else if (uiState.status.contains("failed", ignoreCase = true) || uiState.status.contains("error", ignoreCase = true))
                                MaterialTheme.typography.titleMedium.copy(color = MaterialTheme.colorScheme.error)
                            else
                                MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f)
                )
                if (uiState.verificationResultItems.isNotEmpty()) {
                    Row {
                        IconButton(onClick = onClickCopy) {
                            Icon(
                                painterResource(R.drawable.ic_content_copy),
                                contentDescription = "Copy Results"
                            )
                        }
                        IconButton(onClick = onClickShare) {
                            Icon(
                                painterResource(R.drawable.ic_share),
                                contentDescription = "Share Results"
                            )
                        }
                    }
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
        }


        // Display structured verification results
        if (uiState.verificationResultItems.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    uiState.verificationResultItems.forEachIndexed { index, item ->
                        val textStyle = if (item.isHeader) {
                            MaterialTheme.typography.titleSmall
                        } else {
                            MaterialTheme.typography.bodyMedium
                        }
                        val itemPadding = when (item.indentLevel) {
                            1 -> Modifier.padding(start = 16.dp)
                            2 -> Modifier.padding(start = 32.dp)
                            else -> Modifier
                        }

                        Column(modifier = itemPadding) {
                            if (item.isHeader) {
                                Text(
                                    text = item.label,
                                    style = textStyle,
                                    modifier = Modifier.padding(top = if (index > 0) 8.dp else 0.dp, bottom = 4.dp)
                                )
                            } else {
                                Text(
                                    text = "${item.label}: ${item.value}",
                                    style = textStyle,
                                    modifier = Modifier.padding(vertical = 2.dp)
                                )
                            }
                        }
                        if (item.isHeader && item.indentLevel == 0 && index < uiState.verificationResultItems.lastIndex) {
                             Divider(modifier = Modifier.padding(vertical = 6.dp))
                        } else if (!item.isHeader && index < uiState.verificationResultItems.lastIndex && uiState.verificationResultItems[index+1].indentLevel <= item.indentLevel && !uiState.verificationResultItems[index+1].isHeader) {
                            // Optional: finer grained divider, only if next item is not a header and at same or lower indent
                            // Divider(modifier = Modifier.padding(start = (item.indentLevel * 16).dp, top = 2.dp, bottom = 2.dp).alpha(0.5f))
                        }
                    }
                }
            }
            Spacer(modifier = Modifier.height(16.dp))

            // Device Info and Security Info are now part of verificationResultItems
            // So, the dedicated display sections below are no longer needed.
        }
    }
}

@Preview
@Composable
private fun KeyAttestationScreenPreview() {
    val previewItems = listOf(
        AttestationInfoItem("Session ID", "preview-session-id"),
        AttestationInfoItem("Is Verified", "true"),
        AttestationInfoItem("Attestation Version", "4"),
        AttestationInfoItem("Attestation Security Level", "1"),
        AttestationInfoItem("KeyMint Version", "1"),
        AttestationInfoItem("KeyMint Security Level", "1"),
        AttestationInfoItem("Software Enforced Properties", "", isHeader = true),
        AttestationInfoItem("Attestation Application ID", "", indentLevel = 1, isHeader = true),
        AttestationInfoItem("Application ID", "com.example.preview", indentLevel = 2),
        AttestationInfoItem("Version Code", "101", indentLevel = 2),
        AttestationInfoItem("Signature", "aabbccddeeff...", indentLevel = 2),
        AttestationInfoItem("Creation Datetime", "2023-01-01T10:00:00.000Z", indentLevel = 1),
        AttestationInfoItem("Algorithm", "1", indentLevel = 1),
        AttestationInfoItem("TEE Enforced Properties", "", isHeader = true),
        AttestationInfoItem("Origin", "0", indentLevel = 1),

        // Sample Device Info
        AttestationInfoItem("Device Info", "", isHeader = true, indentLevel = 0),
        AttestationInfoItem("Brand", "Google", indentLevel = 1),
        AttestationInfoItem("Model", "Pixel Preview", indentLevel = 1),
        AttestationInfoItem("SDK Int", "33", indentLevel = 1),

        // Sample Security Info
        AttestationInfoItem("Security Info", "", isHeader = true, indentLevel = 0),
        AttestationInfoItem("Is Device Lock Enabled", "true", indentLevel = 1),
        AttestationInfoItem("Has Strongbox", "true", indentLevel = 1),
    )
    KeyAttestationScreen(
        uiState = KeyAttestationUiState(
            nonce = "PREVIEW_NONCE_67890",
            challenge = "PREVIEW_CHALLENGE_ABCDE",
            selectedKeyType = CryptoAlgorithm.RSA,
            status = "Verification successful.",
            verificationResultItems = previewItems
        ),
        onSelectedKeyTypeChange = { System.out.println("Preview: Key type changed to ${it.label}") },
        onFetchNonceChallenge = { System.out.println("Preview: Fetch Nonce/Challenge clicked") },
        onGenerateKeyPair = { System.out.println("Preview: Generate KeyPair clicked") },
        onRequestVerifyKeyAttestation = { System.out.println("Preview: Request Verify KeyAttestation clicked") },
        onClickCopy = { System.out.println("Preview: onClickCopy called") },
        onClickShare = { System.out.println("Preview: onClickShare called") }
    )
}
