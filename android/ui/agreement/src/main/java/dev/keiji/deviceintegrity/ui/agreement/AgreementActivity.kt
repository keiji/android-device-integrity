package dev.keiji.deviceintegrity.ui.agreement

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.windowInsetsPadding
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.agreement.R
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dagger.hilt.android.AndroidEntryPoint
import dev.keiji.deviceintegrity.provider.contract.UrlProvider
import dev.keiji.deviceintegrity.ui.nav.contract.ExpressModeNavigator
import dev.keiji.deviceintegrity.ui.nav.contract.MainNavigator
import dev.keiji.deviceintegrity.ui.theme.ButtonHeight
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme
import kotlinx.coroutines.flow.collectLatest
import javax.inject.Inject

@AndroidEntryPoint
class AgreementActivity : ComponentActivity() {

    @Inject
    lateinit var mainNavigator: MainNavigator

    @Inject
    lateinit var expressModeNavigator: ExpressModeNavigator

    private val viewModel: AgreementViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
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
                        onCheckImmediately = {
                            startActivity(expressModeNavigator.newIntent(this@AgreementActivity))
                        },
                        onConfigureDetails = {
                            startActivity(mainNavigator.newIntent(this@AgreementActivity))
                            finish()
                        },
                        onExit = {
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
    onCheckImmediately: () -> Unit,
    onConfigureDetails: () -> Unit,
    onExit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.systemBars)
            .padding(16.dp),
        verticalArrangement = Arrangement.Top,
        horizontalAlignment = Alignment.Start
    ) {
        Text(
            text = stringResource(R.string.agreement_screen_title),
            style = MaterialTheme.typography.displaySmall
        )
        Spacer(modifier = Modifier.height(32.dp))
        Text(text = stringResource(R.string.agreement_screen_description))
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.agreement_screen_privacy_policy_link),
            modifier = Modifier.clickable {
                onOpenPrivacyPolicy()
            },
            color = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.weight(1f))
        Button(
            onClick = onCheckImmediately,
            modifier = Modifier
                .fillMaxWidth()
                .height(64.dp)
        ) {
            Text(stringResource(R.string.agreement_screen_check_immediately))
        }
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedButton(
            onClick = onConfigureDetails,
            modifier = Modifier
                .fillMaxWidth()
                .height(64.dp)
        ) {
            Text(stringResource(R.string.agreement_screen_agree_button))
        }
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = onExit,
            modifier = Modifier
                .fillMaxWidth()
                .height(64.dp)
        ) {
            Text(stringResource(R.string.agreement_screen_disagree_button))
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
            onCheckImmediately = {},
            onConfigureDetails = {},
            onExit = {}
        )
    }
}
