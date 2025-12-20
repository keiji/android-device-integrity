package dev.keiji.deviceintegrity.ui.express_mode

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

@Composable
fun ExpressModeScreen(
    uiState: ExpressModeUiState
) {
    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp),
            horizontalAlignment = Alignment.Start
        ) {
            Text(
                text = "デバイスの完全性を確認します",
                style = MaterialTheme.typography.displaySmall
            )
            Spacer(modifier = Modifier.height(32.dp))
            Text(
                text = "Play Integrity APIを実行しています",
            )
            Spacer(modifier = Modifier.height(16.dp))

            // HorizontalProgress
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
