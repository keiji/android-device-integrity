package dev.keiji.deviceintegrity.ui.main.playintegrity

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.main.R
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import android.content.Intent

@Composable
fun StatusDisplayArea(
    isLoading: Boolean,
    errorMessages: List<String>,
    statusText: String,
    tokenPayload: TokenPayloadExternal?,
    currentSessionId: String,
    modifier: Modifier = Modifier
) {
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current

    val textToShare = buildString {
        if (currentSessionId.isNotBlank()) {
            append("Current Session ID: $currentSessionId\n\n")
        }
        if (tokenPayload != null) {
            append(formatTokenPayload(tokenPayload, currentSessionId))
        } else {
            append(statusText)
        }
    }

    Column(modifier = modifier.fillMaxWidth()) {
        if (isLoading) {
            CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
        } else if (errorMessages.isNotEmpty()) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                IconButton(
                    onClick = {
                        clipboardManager.setText(AnnotatedString(errorMessages.joinToString("\n")))
                    }
                ) {
                    Icon(painterResource(id = R.drawable.ic_content_copy), contentDescription = "Copy Error")
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            SelectionContainer {
                Text(
                    text = "Error: ${errorMessages.joinToString("\n")}",
                    modifier = Modifier.fillMaxWidth()
                )
            }
        } else if (tokenPayload != null) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                IconButton(
                    onClick = {
                        clipboardManager.setText(AnnotatedString(formatTokenPayload(tokenPayload, currentSessionId)))
                    }
                ) {
                    Icon(painterResource(id = R.drawable.ic_content_copy), contentDescription = "Copy")
                }
                IconButton(
                    onClick = {
                        val sendIntent: Intent = Intent().apply {
                            action = Intent.ACTION_SEND
                            putExtra(Intent.EXTRA_TEXT, textToShare)
                            type = "text/plain"
                        }
                        val shareIntent = Intent.createChooser(sendIntent, null)
                        context.startActivity(shareIntent)
                    }
                ) {
                    Icon(painterResource(id = R.drawable.ic_share), contentDescription = "Share")
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            SelectionContainer {
                Column {
                    if (currentSessionId.isNotBlank()) {
                        Text("Current Session ID: $currentSessionId")
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                    DisplayTokenResponse(tokenPayload)
                }
            }
        } else {
            if (statusText.isNotEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    IconButton(
                        onClick = { clipboardManager.setText(AnnotatedString(statusText)) }
                    ) {
                        Icon(painterResource(id = R.drawable.ic_content_copy), contentDescription = "Copy")
                    }
                    IconButton(
                        onClick = {
                            val sendIntent: Intent = Intent().apply {
                                action = Intent.ACTION_SEND
                                putExtra(Intent.EXTRA_TEXT, textToShare)
                                type = "text/plain"
                            }
                            val shareIntent = Intent.createChooser(sendIntent, null)
                            context.startActivity(shareIntent)
                        }
                    ) {
                        Icon(painterResource(id = R.drawable.ic_share), contentDescription = "Share")
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }
            SelectionContainer {
                Text(
                    text = statusText,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }
    }
}

fun formatTimestamp(timestampMillis: String?): String {
    if (timestampMillis == null) return "N/A"
    return try {
        val millis = timestampMillis.toLong()
        val date = Date(millis)
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.getDefault())
        format.timeZone = TimeZone.getDefault()
        format.format(date)
    } catch (e: NumberFormatException) {
        "N/A (Invalid Timestamp)"
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
        Text("  Timestamp: ${formatTimestamp(tokenPayload.requestDetails?.timestampMillis)}")

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

internal fun formatTokenPayload(
    tokenPayload: TokenPayloadExternal?,
    currentSessionId: String? = null
): String {
    if (tokenPayload == null) {
        return "Response: N/A"
    }
    return buildString {
        if (!currentSessionId.isNullOrBlank()) {
            append("Current Session ID: $currentSessionId\n\n")
        }
        append(
            """
            Request Details:
              Package Name: ${tokenPayload.requestDetails?.requestPackageName ?: "N/A"}
              Nonce: ${tokenPayload.requestDetails?.nonce ?: "N/A"}
              Request Hash: ${tokenPayload.requestDetails?.requestHash ?: "N/A"}
              Timestamp: ${formatTimestamp(tokenPayload.requestDetails?.timestampMillis)}

            App Integrity:
            """.trimIndent()
        )
        append(
            """
              Recognition Verdict: ${tokenPayload.appIntegrity?.appRecognitionVerdict ?: "N/A"}
              Package Name: ${tokenPayload.appIntegrity?.packageName ?: "N/A"}
              Certificate SHA256: ${tokenPayload.appIntegrity?.certificateSha256Digest?.joinToString() ?: "N/A"}
              Version Code: ${tokenPayload.appIntegrity?.versionCode ?: "N/A"}

            Device Integrity:
            """.trimIndent()
        )
        append(
            """
              Recognition Verdict: ${tokenPayload.deviceIntegrity?.deviceRecognitionVerdict?.joinToString() ?: "N/A"}
              SDK Version: ${tokenPayload.deviceIntegrity?.deviceAttributes?.sdkVersion ?: "N/A"}
              Device Activity Level: ${tokenPayload.deviceIntegrity?.recentDeviceActivity?.deviceActivityLevel ?: "N/A"}

            Account Details:
            """.trimIndent()
        )
        append(
            """
              Licensing Verdict: ${tokenPayload.accountDetails?.appLicensingVerdict ?: "N/A"}

            Environment Details:
              App Access Risk Verdict: ${tokenPayload.environmentDetails?.appAccessRiskVerdict?.appsDetected?.joinToString() ?: "N/A"}
              Play Protect Verdict: ${tokenPayload.environmentDetails?.playProtectVerdict ?: "N/A"}
            """.trimIndent()
        )
    }.trimIndent()
}
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
