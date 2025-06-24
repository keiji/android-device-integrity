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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

@Composable
fun KeyAttestationScreen(
    uiState: KeyAttestationUiState,
    onNonceChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top
    ) {
        Text(text = "nonceを入力してください")

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedTextField(
            value = uiState.nonce,
            onValueChange = { onNonceChange(it) }, // Use callback
            label = { Text("Nonce (Hex)") },
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Characters,
                autoCorrect = false,
                keyboardType = KeyboardType.Ascii
            ),
            singleLine = true,
        )

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = { onSubmit() }, // Use callback
            modifier = Modifier.fillMaxWidth()
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
        onSubmit = { System.out.println("Preview: Submit clicked") }
    )
}
