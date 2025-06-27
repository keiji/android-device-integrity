package dev.keiji.deviceintegrity.ui.main.playintegrity

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.main.R
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal

@Composable
fun StatusDisplayArea(
    isLoading: Boolean,
    errorMessages: List<String>,
    statusText: String,
    tokenPayload: TokenPayloadExternal?,
    modifier: Modifier = Modifier
) {
    val clipboardManager = LocalClipboardManager.current

    Box(modifier = modifier.fillMaxWidth()) {
        if (isLoading) {
            CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
        } else if (errorMessages.isNotEmpty()) {
            Text(
                text = "Error: ${errorMessages.joinToString("\n")}",
                modifier = Modifier.align(Alignment.TopStart)
            )
        } else if (tokenPayload != null) {
            DisplayTokenResponse(tokenPayload)
            IconButton(
                onClick = {
                    val textToCopy = formatTokenPayload(tokenPayload)
                    clipboardManager.setText(AnnotatedString(textToCopy))
                },
                modifier = Modifier.align(Alignment.TopEnd)
            ) {
                    Icon(painterResource(id = R.drawable.ic_content_copy), contentDescription = "Copy")
            }
        } else {
            Text(
                text = statusText,
                modifier = Modifier.align(Alignment.TopStart)
            )
            if (statusText.isNotEmpty()) {
                IconButton(
                    onClick = { clipboardManager.setText(AnnotatedString(statusText)) },
                    modifier = Modifier.align(Alignment.TopEnd)
                ) {
                        Icon(painterResource(id = R.drawable.ic_content_copy), contentDescription = "Copy")
                }
            }
        }
    }
}

@Composable
fun DisplayTokenResponse(tokenPayload: TokenPayloadExternal?) {
    if (tokenPayload == null) {
        Text("Response: N/A")
        return
    }
    Column {
        Text("Request Details:")
        Text("  Package Name: ${tokenPayload.requestDetails?.requestPackageName ?: "N/A"}")
        Text("  Nonce: ${tokenPayload.requestDetails?.nonce ?: "N/A"}")
        Text("  Request Hash: ${tokenPayload.requestDetails?.requestHash ?: "N/A"}")
        Text("  Timestamp: ${tokenPayload.requestDetails?.timestampMillis ?: "N/A"}")

        Spacer(modifier = Modifier.height(8.dp))
        Text("App Integrity:")
        Text("  Recognition Verdict: ${tokenPayload.appIntegrity?.appRecognitionVerdict ?: "N/A"}")
        Text("  Package Name: ${tokenPayload.appIntegrity?.packageName ?: "N/A"}")
        Text("  Certificate SHA256: ${tokenPayload.appIntegrity?.certificateSha256Digest?.joinToString() ?: "N/A"}")
        Text("  Version Code: ${tokenPayload.appIntegrity?.versionCode ?: "N/A"}")

        Spacer(modifier = Modifier.height(8.dp))
        Text("Device Integrity:")
        Text("  Recognition Verdict: ${tokenPayload.deviceIntegrity?.deviceRecognitionVerdict?.joinToString() ?: "N/A"}")
        Text("  SDK Version: ${tokenPayload.deviceIntegrity?.deviceAttributes?.sdkVersion ?: "N/A"}")
        Text("  Device Activity Level: ${tokenPayload.deviceIntegrity?.recentDeviceActivity?.deviceActivityLevel ?: "N/A"}")


        Spacer(modifier = Modifier.height(8.dp))
        Text("Account Details:")
        Text("  Licensing Verdict: ${tokenPayload.accountDetails?.appLicensingVerdict ?: "N/A"}")

        Spacer(modifier = Modifier.height(8.dp))
        Text("Environment Details:")
        Text("  App Access Risk Verdict: ${tokenPayload.environmentDetails?.appAccessRiskVerdict?.appsDetected?.joinToString() ?: "N/A"}")
        Text("  Play Protect Verdict: ${tokenPayload.environmentDetails?.playProtectVerdict ?: "N/A"}")
    }
}

internal fun formatTokenPayload(tokenPayload: TokenPayloadExternal?): String {
    if (tokenPayload == null) {
        return "Response: N/A"
    }
    return """
        Request Details:
          Package Name: ${tokenPayload.requestDetails?.requestPackageName ?: "N/A"}
          Nonce: ${tokenPayload.requestDetails?.nonce ?: "N/A"}
          Request Hash: ${tokenPayload.requestDetails?.requestHash ?: "N/A"}
          Timestamp: ${tokenPayload.requestDetails?.timestampMillis ?: "N/A"}

        App Integrity:
          Recognition Verdict: ${tokenPayload.appIntegrity?.appRecognitionVerdict ?: "N/A"}
          Package Name: ${tokenPayload.appIntegrity?.packageName ?: "N/A"}
          Certificate SHA256: ${tokenPayload.appIntegrity?.certificateSha256Digest?.joinToString() ?: "N/A"}
          Version Code: ${tokenPayload.appIntegrity?.versionCode ?: "N/A"}

        Device Integrity:
          Recognition Verdict: ${tokenPayload.deviceIntegrity?.deviceRecognitionVerdict?.joinToString() ?: "N/A"}
          SDK Version: ${tokenPayload.deviceIntegrity?.deviceAttributes?.sdkVersion ?: "N/A"}
          Device Activity Level: ${tokenPayload.deviceIntegrity?.recentDeviceActivity?.deviceActivityLevel ?: "N/A"}

        Account Details:
          Licensing Verdict: ${tokenPayload.accountDetails?.appLicensingVerdict ?: "N/A"}

        Environment Details:
          App Access Risk Verdict: ${tokenPayload.environmentDetails?.appAccessRiskVerdict?.appsDetected?.joinToString() ?: "N/A"}
          Play Protect Verdict: ${tokenPayload.environmentDetails?.playProtectVerdict ?: "N/A"}
    """.trimIndent()
}
