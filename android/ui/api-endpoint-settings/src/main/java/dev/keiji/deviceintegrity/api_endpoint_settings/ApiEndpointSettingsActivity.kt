package dev.keiji.deviceintegrity.api_endpoint_settings

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme
import android.widget.Toast
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class ApiEndpointSettingsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            DeviceIntegrityTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val viewModel: ApiEndpointSettingsViewModel = hiltViewModel()
                    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
                    val context = LocalContext.current

                    LaunchedEffect(uiState.saveSuccess) {
                        if (uiState.saveSuccess) {
                            Toast.makeText(context, "API Endpoint saved successfully!", Toast.LENGTH_SHORT).show()
                            viewModel.resetSaveSuccess() // Reset the flag in ViewModel
                            finish() // Close the activity
                        }
                    }

                    ApiEndpointSettingsScreen(
                        uiState = uiState,
                        onEditingPlayIntegrityUrlChange = viewModel::updateEditingPlayIntegrityUrl,
                        onEditingKeyAttestationUrlChange = viewModel::updateEditingKeyAttestationUrl,
                        onSaveClick = viewModel::saveApiEndpoints
                    )
                }
            }
        }
    }
}
