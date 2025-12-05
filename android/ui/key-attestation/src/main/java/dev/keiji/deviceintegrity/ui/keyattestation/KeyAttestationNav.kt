package dev.keiji.deviceintegrity.ui.keyattestation

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import dev.keiji.deviceintegrity.ui.R
import dev.keiji.deviceintegrity.ui.nav.contract.AppScreen

fun NavGraphBuilder.keyAttestationScreen(
) {
    composable(AppScreen.KeyAttestation.route) {
        val keyAttestationViewModel: KeyAttestationViewModel = hiltViewModel()
        val keyAttestationUiState by keyAttestationViewModel.uiState.collectAsStateWithLifecycle()
        val currentContext = LocalContext.current

        LaunchedEffect(keyAttestationViewModel.shareEventFlow) {
            keyAttestationViewModel.shareEventFlow.collect { textToShare ->
                val sendIntent: Intent = Intent().apply {
                    action = Intent.ACTION_SEND
                    putExtra(Intent.EXTRA_TEXT, textToShare)
                    type = "text/plain"
                }
                val shareIntent = Intent.createChooser(sendIntent, null)
                currentContext.startActivity(shareIntent)
            }
        }

        LaunchedEffect(keyAttestationViewModel.copyEventFlow) {
            keyAttestationViewModel.copyEventFlow.collect { textToCopy ->
                val clipboard =
                    currentContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText(
                    currentContext.getString(dev.keiji.deviceintegrity.ui.keyattestation.R.string.key_attestation_result_label),
                    textToCopy
                )
                clipboard.setPrimaryClip(clip)
                Toast.makeText(
                    currentContext,
                    currentContext.getString(R.string.copied_to_clipboard),
                    Toast.LENGTH_SHORT
                ).show()
            }
        }

        KeyAttestationScreen(
            uiState = keyAttestationUiState,
            onSelectedKeyTypeChange = { keyAttestationViewModel.onSelectedKeyTypeChange(it) },
            onPreferStrongBoxChanged = { keyAttestationViewModel.onPreferStrongBoxChanged(it) },
            onFetchNonceChallenge = { keyAttestationViewModel.fetchNonceChallenge() },
            onGenerateKeyPair = { keyAttestationViewModel.generateKeyPair() },
            onRequestVerifyKeyAttestation = { keyAttestationViewModel.requestVerifyKeyAttestation() },
            onClickCopy = { keyAttestationViewModel.onCopyResultsClicked() },
            onClickShare = { keyAttestationViewModel.onShareResultsClicked() }
        )
    }
}
