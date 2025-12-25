package dev.keiji.deviceintegrity.ui.express_mode

import android.app.Activity
import androidx.compose.runtime.getValue
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.platform.LocalContext

const val EXPRESS_MODE_ROUTE = "express_mode"

fun NavGraphBuilder.expressModeScreen(
    onCopyClick: () -> Unit = {},
    onShareClick: () -> Unit = {},
    onNavigateUp: () -> Unit = {},
    onExitApp: () -> Unit = {},
) {
    composable(EXPRESS_MODE_ROUTE) {
        val viewModel: ExpressModeViewModel = hiltViewModel()
        val uiState by viewModel.uiState.collectAsState()
        val uiEvent by viewModel.uiEvent.collectAsState()

        ExpressModeScreen(
            uiState = uiState,
            onCopyClick = onCopyClick,
            onShareClick = onShareClick,
            onBack = onNavigateUp,
            onExitApp = onExitApp
        )
    }
}
