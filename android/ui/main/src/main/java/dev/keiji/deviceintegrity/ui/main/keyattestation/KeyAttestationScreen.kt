package dev.keiji.deviceintegrity.ui.main.keyattestation

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
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
import dev.keiji.deviceintegrity.ui.theme.ButtonHeight

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyAttestationScreen(
    uiState: KeyAttestationUiState,
    onSelectedKeyTypeChange: (String) -> Unit,
    onFetchNonceChallenge: () -> Unit,
    onGenerateKeyPair: () -> Unit,
    onRequestVerifyKeyAttestation: () -> Unit,
) {
    val scrollState = rememberScrollState()
    var keyTypeExpanded by remember { mutableStateOf(false) }
    val keyTypes = listOf("EC", "ECDH", "RSA") // TODO: Move to ViewModel or constants

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
        Text(text = "Nonce: ${uiState.nonce}")
        Spacer(modifier = Modifier.height(8.dp))
        Text(text = "Challenge: ${uiState.challenge}")

        Spacer(modifier = Modifier.height(16.dp))

        Text(text = "Step2. 生成するキーペアの種類を設定")
        Spacer(modifier = Modifier.height(8.dp))

        Box(modifier = Modifier.fillMaxWidth()) {
            ExposedDropdownMenuBox(
                expanded = keyTypeExpanded,
                onExpandedChange = { keyTypeExpanded = !keyTypeExpanded }
            ) {
                TextField(
                    value = uiState.selectedKeyType,
                    onValueChange = {}, // This remains empty as direct text input is not intended
                    readOnly = true,
                    label = { Text("Key Pair Type") },
                    trailingIcon = {
                        ExposedDropdownMenuDefaults.TrailingIcon(expanded = keyTypeExpanded)
                    },
                    colors = ExposedDropdownMenuDefaults.textFieldColors(),
                    modifier = Modifier.menuAnchor().fillMaxWidth()
                )
                ExposedDropdownMenu(
                    expanded = keyTypeExpanded,
                    onDismissRequest = { keyTypeExpanded = false }
                ) {
                    keyTypes.forEach { selectionOption ->
                        DropdownMenuItem(
                            text = { Text(selectionOption) },
                            onClick = {
                                onSelectedKeyTypeChange(selectionOption)
                                keyTypeExpanded = false
                            }
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
                .height(ButtonHeight)
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
                .height(ButtonHeight)
        ) {
            Text(text = "Request Verify KeyAttestation")
        }

        Spacer(modifier = Modifier.height(16.dp))
        Text(text = uiState.status)
    }
}

@Preview
@Composable
private fun KeyAttestationScreenPreview() {
    KeyAttestationScreen(
        uiState = KeyAttestationUiState(
            nonce = "PREVIEW_NONCE_67890",
            challenge = "PREVIEW_CHALLENGE_ABCDE",
            selectedKeyType = "RSA",
            status = "Previewing KeyAttestation Screen..."
        ),
        onSelectedKeyTypeChange = { System.out.println("Preview: Key type changed to $it") },
        onFetchNonceChallenge = { System.out.println("Preview: Fetch Nonce/Challenge clicked") },
        onGenerateKeyPair = { System.out.println("Preview: Generate KeyPair clicked") },
        onRequestVerifyKeyAttestation = { System.out.println("Preview: Request Verify KeyAttestation clicked") }
    )
}
