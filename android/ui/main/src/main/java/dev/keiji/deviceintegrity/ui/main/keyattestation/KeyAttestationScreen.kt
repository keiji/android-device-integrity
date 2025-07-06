package dev.keiji.deviceintegrity.ui.main.keyattestation

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.domain.model.CryptoAlgorithm
import dev.keiji.deviceintegrity.ui.theme.ButtonHeight

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyAttestationScreen(
    uiState: KeyAttestationUiState,
    onNonceChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onAlgorithmSelected: (CryptoAlgorithm) -> Unit,
    availableAlgorithms: List<CryptoAlgorithm>,
    selectedAlgorithm: CryptoAlgorithm?,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top
    ) {
        Text(text = "nonceを入力してください")

        var expanded by remember { mutableStateOf(false) }

        Spacer(modifier = Modifier.height(8.dp))

        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = !expanded },
            modifier = Modifier.fillMaxWidth()
        ) {
            OutlinedTextField(
                value = selectedAlgorithm?.label ?: "Select Algorithm",
                onValueChange = {},
                readOnly = true,
                label = { Text("Cryptographic Algorithm") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.menuAnchor().fillMaxWidth()
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                availableAlgorithms.forEach { algorithm ->
                    DropdownMenuItem(
                        text = { Text(algorithm.label) },
                        onClick = {
                            onAlgorithmSelected(algorithm)
                            expanded = false
                        }
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedTextField(
            value = uiState.nonce,
            onValueChange = { onNonceChange(it) }, // Use callback
            label = { Text("Nonce (Hex)") },
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Characters,
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Ascii
            ),
            singleLine = true,
        )

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = { onSubmit() }, // Use callback
            modifier = Modifier
                .fillMaxWidth()
                .height(ButtonHeight)
        ) {
            Text(text = "送信")
        }

        if (uiState.isLoading) {
            Spacer(modifier = Modifier.height(16.dp))
            Text("Loading...")
        }

        if (uiState.result.isNotEmpty()) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(text = uiState.result)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class) // Required for ExposedDropdownMenuBox
@Preview
@Composable
private fun KeyAttestationScreenPreview() {
    KeyAttestationScreen(
        uiState = KeyAttestationUiState(
            nonce = "PREVIEW_NONCE_12345",
            isLoading = true,
            result = "Previewing result text..."
        ),
        onNonceChange = { System.out.println("Preview: Nonce changed to $it") },
        onSubmit = { System.out.println("Preview: Submit clicked") },
        onAlgorithmSelected = { System.out.println("Preview: Algorithm selected: ${it.label}") },
        availableAlgorithms = CryptoAlgorithm.values().toList(),
        selectedAlgorithm = CryptoAlgorithm.RSA
    )
}
