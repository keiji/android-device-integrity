package dev.keiji.deviceintegrity.ui.express_mode

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
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
