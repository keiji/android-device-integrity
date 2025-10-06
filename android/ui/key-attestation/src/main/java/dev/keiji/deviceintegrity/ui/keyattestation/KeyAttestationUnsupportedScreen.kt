package dev.keiji.deviceintegrity.ui.keyattestation

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import dev.keiji.deviceintegrity.ui.keyattestation.R

@Composable
fun KeyAttestationUnsupportedScreen(
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Text(text = stringResource(id = R.string.key_attestation_unsupported))
    }
}

@Preview
@Composable
fun KeyAttestationUnsupportedScreenPreview() {
    KeyAttestationUnsupportedScreen()
}
