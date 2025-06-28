package dev.keiji.deviceintegrity.ui.agreement

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.activity.viewModels
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dagger.hilt.android.AndroidEntryPoint
import dev.keiji.deviceintegrity.provider.contract.UrlProvider
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme
import kotlinx.coroutines.flow.collectLatest

@AndroidEntryPoint
class AgreementActivity : ComponentActivity() {

    private val viewModel: AgreementViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            DeviceIntegrityTheme {
                val uriHandler = LocalUriHandler.current
                LaunchedEffect(Unit) {
                    viewModel.eventFlow.collectLatest { event ->
                        when (event) {
                            is UiEvent.OpenPrivacyPolicy -> {
                                uriHandler.openUri(event.url)
                            }
                        }
                    }
                }

                val uiState by viewModel.uiState.collectAsStateWithLifecycle()

                Surface(modifier = Modifier.fillMaxSize()) {
                    AgreementScreen(
                        uiState = uiState,
                        onOpenPrivacyPolicy = { viewModel.openPrivacyPolicy() },
                        onAgree = {
                            setResult(Activity.RESULT_OK)
                            finish()
                        },
                        onDisagree = {
                            setResult(Activity.RESULT_CANCELED)
                            finish()
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun AgreementScreen(
    uiState: AgreementUiState,
    onOpenPrivacyPolicy: () -> Unit,
    onAgree: () -> Unit,
    onDisagree: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.Top,
        horizontalAlignment = Alignment.Start
    ) {
        Text(
            text = "Device Integrity",
            style = MaterialTheme.typography.headlineLarge
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(text = "プライバリーポリシーを確認して利用を開始してください")
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "プライバリーポリシー",
            modifier = Modifier.clickable {
                onOpenPrivacyPolicy()
            },
            color = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.weight(1f))
        OutlinedButton(
            onClick = onAgree,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("利用を開始する")
        }
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = onDisagree,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("アプリを終了")
        }
    }
}

@Preview(showBackground = true)
@Composable
fun AgreementScreenPreview() {
    MaterialTheme {
        AgreementScreen(
            uiState = AgreementUiState(),
            onOpenPrivacyPolicy = {},
            onAgree = {},
            onDisagree = {}
        )
    }
}
