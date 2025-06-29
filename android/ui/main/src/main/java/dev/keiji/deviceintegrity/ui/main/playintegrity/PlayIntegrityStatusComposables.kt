package dev.keiji.deviceintegrity.ui.main.playintegrity

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
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
import dev.keiji.deviceintegrity.api.playintegrity.DeviceInfo
import dev.keiji.deviceintegrity.api.playintegrity.SecurityInfo
import dev.keiji.deviceintegrity.api.playintegrity.TokenPayloadExternal
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import android.content.Intent

@Composable
fun StatusDisplayArea(
    progressValue: Float,
    errorMessages: List<String>,
    statusText: String,
    playIntegrityResponse: TokenPayloadExternal?,
    deviceInfo: DeviceInfo?,
    securityInfo: SecurityInfo?,
    currentSessionId: String,
    modifier: Modifier = Modifier
) {
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current

    val textToShare = buildString {
        if (currentSessionId.isNotBlank()) {
            append("Current Session ID: $currentSessionId\n\n")
        }
        append(
            formatDisplayOutput(
                playIntegrityResponse = playIntegrityResponse,
                deviceInfo = deviceInfo,
                securityInfo = securityInfo,
                statusText = if (playIntegrityResponse == null && deviceInfo == null && securityInfo == null) statusText else ""
            )
        )
    }

    Column(modifier = modifier.fillMaxWidth()) {
        // Progress Indicator
        when (progressValue) {
            PlayIntegrityProgressConstants.INDETERMINATE_PROGRESS -> {
                CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
                Spacer(modifier = Modifier.height(8.dp)) // Add some space below the progress indicator
            }
            else -> {
                if (progressValue > PlayIntegrityProgressConstants.NO_PROGRESS) { // For LinearProgressIndicator
                    LinearProgressIndicator(
                        progress = progressValue,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp)) // Add some space below the progress bar
                }
                // If progressValue == PlayIntegrityProgressConstants.NO_PROGRESS, show nothing for progress
            }
        }

        // Content (Error messages, response, or status text)
        if (errorMessages.isNotEmpty()) {
            // Always show error messages regardless of progressValue
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
        } else if (progressValue == PlayIntegrityProgressConstants.NO_PROGRESS) {
            // Show response or status text only when not loading (progressValue == NO_PROGRESS) and no errors
            if (playIntegrityResponse != null || deviceInfo != null || securityInfo != null) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    IconButton(
                        onClick = {
                            clipboardManager.setText(AnnotatedString(textToShare)) // Use already formatted textToShare
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
                        DisplayFormattedResponse(
                            playIntegrityResponse = playIntegrityResponse,
                            deviceInfo = deviceInfo,
                            securityInfo = securityInfo
                        )
                    }
                }
            } else if (statusText.isNotEmpty()) {
                // Show status text if no response data but status text exists
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    IconButton(
                        onClick = { clipboardManager.setText(AnnotatedString(statusText)) }
                    ) {
                        Icon(painterResource(id = R.drawable.ic_content_copy), contentDescription = "Copy Status")
                    }
                    IconButton(
                        onClick = {
                            val sendIntent: Intent = Intent().apply {
                                action = Intent.ACTION_SEND
                                // textToShare should be just statusText if playIntegrityResponse, deviceInfo and securityInfo are null
                                val contentToShare = if (playIntegrityResponse == null && deviceInfo == null && securityInfo == null) statusText else textToShare
                                putExtra(Intent.EXTRA_TEXT, contentToShare)
                                type = "text/plain"
                            }
                            val shareIntent = Intent.createChooser(sendIntent, null)
                            context.startActivity(shareIntent)
                        }
                    ) {
                        Icon(painterResource(id = R.drawable.ic_share), contentDescription = "Share Status")
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                SelectionContainer {
                    Text(
                        text = statusText,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }
        // If progressValue is not NO_PROGRESS and no error messages, only progress indicator will be shown,
        // unless it's a LinearProgressIndicator (progressValue > NO_PROGRESS), in which case status text is also shown.
        // If progressValue is NO_PROGRESS, no errors, no response data, and statusText is empty, nothing will be shown.
        else if (statusText.isNotEmpty() && progressValue > PlayIntegrityProgressConstants.NO_PROGRESS) { // Show status text with LinearProgressIndicator
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                IconButton(
                    onClick = { clipboardManager.setText(AnnotatedString(statusText)) }
                ) {
                    Icon(painterResource(id = R.drawable.ic_content_copy), contentDescription = "Copy Status")
                }
                IconButton(
                    onClick = {
                        val sendIntent: Intent = Intent().apply {
                            action = Intent.ACTION_SEND
                            putExtra(Intent.EXTRA_TEXT, statusText)
                            type = "text/plain"
                        }
                        val shareIntent = Intent.createChooser(sendIntent, null)
                        context.startActivity(shareIntent)
                    }
                ) {
                    Icon(painterResource(id = R.drawable.ic_share), contentDescription = "Share Status")
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            SelectionContainer {
                Text(
                    text = statusText,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }
    }
}

fun formatTimestamp(timestampMillis: Long?): String {
    if (timestampMillis == null) return "N/A"
    return try {
        val millis = timestampMillis // No need to convert toLong()
        val date = Date(millis)
        // Use Z instead of XXX for API level 23 compatibility
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.getDefault())
        format.timeZone = TimeZone.getDefault()
        format.format(date)
    } catch (e: NumberFormatException) {
        "N/A (Invalid Timestamp)"
    }
}

@Composable
fun DisplayFormattedResponse(
    playIntegrityResponse: TokenPayloadExternal?,
    deviceInfo: DeviceInfo?,
    securityInfo: SecurityInfo?
) {
    Column {
        if (playIntegrityResponse == null && deviceInfo == null && securityInfo == null) {
            Text("Response: N/A")
            return
        }

        // Display Play Integrity API Response
        if (playIntegrityResponse != null) {
            Text("Play Integrity API Response:")
            DisplayPlayIntegrityResponse(playIntegrityResponse)
            Spacer(modifier = Modifier.height(16.dp))
        }

        // Display Device Info
        if (deviceInfo != null) {
            Text("Device Info:")
            DisplayDeviceInfo(deviceInfo)
            Spacer(modifier = Modifier.height(16.dp))
        }

        // Display Security Info
        if (securityInfo != null) {
            Text("Security Info:")
            DisplaySecurityInfo(securityInfo)
        }
    }
}

@Composable
fun DisplayPlayIntegrityResponse(playIntegrityResponse: TokenPayloadExternal) {
    // This function is equivalent to the old DisplayTokenResponse
    Column {
        Text("  Request Details:")
        Text("    Package Name: ${playIntegrityResponse.requestDetails?.requestPackageName ?: "N/A"}")
        Text("    Nonce: ${playIntegrityResponse.requestDetails?.nonce ?: "N/A"}")
        Text("    Request Hash: ${playIntegrityResponse.requestDetails?.requestHash ?: "N/A"}")
        Text("    Timestamp: ${formatTimestamp(playIntegrityResponse.requestDetails?.timestampMillis)}")

        Spacer(modifier = Modifier.height(8.dp))
        Text("  App Integrity:")
        Text("    Recognition Verdict: ${playIntegrityResponse.appIntegrity?.appRecognitionVerdict ?: "N/A"}")
        Text("    Package Name: ${playIntegrityResponse.appIntegrity?.packageName ?: "N/A"}")
        Text("    Certificate SHA256: ${playIntegrityResponse.appIntegrity?.certificateSha256Digest?.joinToString() ?: "N/A"}")
        Text("    Version Code: ${playIntegrityResponse.appIntegrity?.versionCode ?: "N/A"}")

        Spacer(modifier = Modifier.height(8.dp))
        Text("  Device Integrity:")
        Text("    Recognition Verdict: ${playIntegrityResponse.deviceIntegrity?.deviceRecognitionVerdict?.joinToString() ?: "N/A"}")
        Text("    SDK Version: ${playIntegrityResponse.deviceIntegrity?.deviceAttributes?.sdkVersion ?: "N/A"}")
        Text("    Device Activity Level: ${playIntegrityResponse.deviceIntegrity?.recentDeviceActivity?.deviceActivityLevel ?: "N/A"}")

        Spacer(modifier = Modifier.height(8.dp))
        Text("  Account Details:")
        Text("    Licensing Verdict: ${playIntegrityResponse.accountDetails?.appLicensingVerdict ?: "N/A"}")

        Spacer(modifier = Modifier.height(8.dp))
        Text("  Environment Details:")
        Text("    App Access Risk Verdict: ${playIntegrityResponse.environmentDetails?.appAccessRiskVerdict?.appsDetected?.joinToString() ?: "N/A"}")
        Text("    Play Protect Verdict: ${playIntegrityResponse.environmentDetails?.playProtectVerdict ?: "N/A"}")
    }
}

@Composable
fun DisplayDeviceInfo(deviceInfo: DeviceInfo) {
    Column {
        Text("  Brand: ${deviceInfo.brand ?: "N/A"}")
        Text("  Model: ${deviceInfo.model ?: "N/A"}")
        Text("  Device: ${deviceInfo.device ?: "N/A"}")
        Text("  Product: ${deviceInfo.product ?: "N/A"}")
        Text("  Manufacturer: ${deviceInfo.manufacturer ?: "N/A"}")
        Text("  Hardware: ${deviceInfo.hardware ?: "N/A"}")
        Text("  Board: ${deviceInfo.board ?: "N/A"}")
        Text("  Bootloader: ${deviceInfo.bootloader ?: "N/A"}")
        Text("  Version Release: ${deviceInfo.versionRelease ?: "N/A"}")
        Text("  SDK Int: ${deviceInfo.sdkInt?.toString() ?: "N/A"}")
        Text("  Fingerprint: ${deviceInfo.fingerprint ?: "N/A"}")
        Text("  Security Patch: ${deviceInfo.securityPatch ?: "N/A"}")
    }
}

@Composable
fun DisplaySecurityInfo(securityInfo: SecurityInfo) {
    Column {
        Text("  Device Lock Enabled: ${securityInfo.isDeviceLockEnabled?.toString() ?: "N/A"}")
        Text("  Biometrics Enabled: ${securityInfo.isBiometricsEnabled?.toString() ?: "N/A"}")
        Text("  Has Class3 Authenticator: ${securityInfo.hasClass3Authenticator?.toString() ?: "N/A"}")
        Text("  Has Strongbox: ${securityInfo.hasStrongbox?.toString() ?: "N/A"}")
    }
}

internal fun formatDisplayOutput(
    playIntegrityResponse: TokenPayloadExternal?,
    deviceInfo: DeviceInfo?,
    securityInfo: SecurityInfo?,
    statusText: String? = null
): String {
    if (playIntegrityResponse == null && deviceInfo == null && securityInfo == null) {
        return statusText ?: "Response: N/A"
    }

    return buildString {
        // Play Integrity API Response
        if (playIntegrityResponse != null) {
            append("Play Integrity API Response:\n")
            append(
                """
                  Request Details:
                    Package Name: ${playIntegrityResponse.requestDetails?.requestPackageName ?: "N/A"}
                    Nonce: ${playIntegrityResponse.requestDetails?.nonce ?: "N/A"}
                    Request Hash: ${playIntegrityResponse.requestDetails?.requestHash ?: "N/A"}
                    Timestamp: ${formatTimestamp(playIntegrityResponse.requestDetails?.timestampMillis)}

                  App Integrity:
                    Recognition Verdict: ${playIntegrityResponse.appIntegrity?.appRecognitionVerdict ?: "N/A"}
                    Package Name: ${playIntegrityResponse.appIntegrity?.packageName ?: "N/A"}
                    Certificate SHA256: ${playIntegrityResponse.appIntegrity?.certificateSha256Digest?.joinToString() ?: "N/A"}
                    Version Code: ${playIntegrityResponse.appIntegrity?.versionCode ?: "N/A"}

                  Device Integrity:
                    Recognition Verdict: ${playIntegrityResponse.deviceIntegrity?.deviceRecognitionVerdict?.joinToString() ?: "N/A"}
                    SDK Version: ${playIntegrityResponse.deviceIntegrity?.deviceAttributes?.sdkVersion ?: "N/A"}
                    Device Activity Level: ${playIntegrityResponse.deviceIntegrity?.recentDeviceActivity?.deviceActivityLevel ?: "N/A"}

                  Account Details:
                    Licensing Verdict: ${playIntegrityResponse.accountDetails?.appLicensingVerdict ?: "N/A"}

                  Environment Details:
                    App Access Risk Verdict: ${playIntegrityResponse.environmentDetails?.appAccessRiskVerdict?.appsDetected?.joinToString() ?: "N/A"}
                    Play Protect Verdict: ${playIntegrityResponse.environmentDetails?.playProtectVerdict ?: "N/A"}
                """.trimIndent()
            )
            append("\n\n") // Add space before the next section
        }

        // Device Info
        if (deviceInfo != null) {
            append("Device Info:\n")
            append(
                """
                  Brand: ${deviceInfo.brand ?: "N/A"}
                  Model: ${deviceInfo.model ?: "N/A"}
                  Device: ${deviceInfo.device ?: "N/A"}
                  Product: ${deviceInfo.product ?: "N/A"}
                  Manufacturer: ${deviceInfo.manufacturer ?: "N/A"}
                  Hardware: ${deviceInfo.hardware ?: "N/A"}
                  Board: ${deviceInfo.board ?: "N/A"}
                  Bootloader: ${deviceInfo.bootloader ?: "N/A"}
                  Version Release: ${deviceInfo.versionRelease ?: "N/A"}
                  SDK Int: ${deviceInfo.sdkInt?.toString() ?: "N/A"}
                  Fingerprint: ${deviceInfo.fingerprint ?: "N/A"}
                  Security Patch: ${deviceInfo.securityPatch ?: "N/A"}
                """.trimIndent()
            )
            append("\n\n") // Add space before the next section
        }

        // Security Info
        if (securityInfo != null) {
            append("Security Info:\n")
            append(
                """
                  Device Lock Enabled: ${securityInfo.isDeviceLockEnabled?.toString() ?: "N/A"}
                  Biometrics Enabled: ${securityInfo.isBiometricsEnabled?.toString() ?: "N/A"}
                  Has Class3 Authenticator: ${securityInfo.hasClass3Authenticator?.toString() ?: "N/A"}
                  Has Strongbox: ${securityInfo.hasStrongbox?.toString() ?: "N/A"}
                """.trimIndent()
            )
        }
    }.trimIndent()
}
