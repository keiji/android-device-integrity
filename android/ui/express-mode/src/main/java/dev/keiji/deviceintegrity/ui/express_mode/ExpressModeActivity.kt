package dev.keiji.deviceintegrity.ui.express_mode

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

class ExpressModeActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            DeviceIntegrityTheme {
                val viewModel: ExpressModeViewModel = viewModel()
                val uiState by viewModel.uiState.collectAsState()
                val uiEvent by viewModel.uiEvent.collectAsState()

                ExpressModeScreen(uiState = uiState)
            }
        }
    }
}

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
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "デバイスの完全性を確認します",
                style = MaterialTheme.typography.titleLarge
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "Play Integrity APIを実行しています",
                style = MaterialTheme.typography.bodyLarge
            )
            Spacer(modifier = Modifier.height(32.dp))

            // CircularProgress with reserved space
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.size(48.dp) // Standard size for CircularProgressIndicator
            ) {
                if (uiState.showProgress) {
                    CircularProgressIndicator()
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // HorizontalProgress
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

private fun Modifier.size(size: androidx.compose.ui.unit.Dp): Modifier {
    return this.width(size).height(size)
}

@Preview(showBackground = true)
@Composable
fun ExpressModeScreenPreview() {
    DeviceIntegrityTheme {
        ExpressModeScreen(
            uiState = ExpressModeUiState(
                showProgress = true,
                progress = 3,
                maxProgress = 5
            )
        )
    }
}
