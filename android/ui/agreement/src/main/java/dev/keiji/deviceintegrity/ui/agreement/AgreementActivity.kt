package dev.keiji.deviceintegrity.ui.agreement

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dagger.hilt.android.AndroidEntryPoint
import dev.keiji.deviceintegrity.provider.contract.UrlProvider
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme
import javax.inject.Inject

@AndroidEntryPoint
class AgreementActivity : ComponentActivity() {

    @Inject
    lateinit var urlProvider: UrlProvider

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            DeviceIntegrityTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AgreementScreen(
                        urlProvider = urlProvider,
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
    urlProvider: UrlProvider,
    onAgree: () -> Unit,
    onDisagree: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val uriHandler = LocalUriHandler.current

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
                uriHandler.openUri(urlProvider.privacyPolicyUrl)
            },
            color = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.height(24.dp))
        OutlinedButton(onClick = onAgree) {
            Text("利用を開始する")
        }
        Spacer(modifier = Modifier.height(8.dp))
        Button(onClick = onDisagree) {
            Text("アプリを終了")
        }
    }
}

@Preview(showBackground = true)
@Composable
fun AgreementScreenPreview() {
    MaterialTheme {
        AgreementScreen(
            urlProvider = object : UrlProvider {
                override val termsOfServiceUrl: String = ""
                override val privacyPolicyUrl: String = ""
                override val aboutAppUrl: String = ""
            },
            onAgree = {},
            onDisagree = {}
        )
    }
}
