package dev.keiji.deviceintegrity.ui.express_mode

import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import androidx.compose.runtime.collectAsState
import androidx.navigation.NavController
import androidx.navigation.compose.navigation

const val EXPRESS_MODE_ROUTE = "express_mode"
const val EXPRESS_MODE_RESULT_ROUTE = "express_mode_result"
const val EXPRESS_MODE_GRAPH_ROUTE = "express_mode_graph"

fun NavGraphBuilder.expressModeScreen(
    navController: NavController,
    onNavigateToOssLicenses: () -> Unit = {},
    onNavigateUp: () -> Unit = {},
    onExitApp: () -> Unit = {},
) {
    navigation(startDestination = EXPRESS_MODE_ROUTE, route = EXPRESS_MODE_GRAPH_ROUTE) {
        composable(EXPRESS_MODE_ROUTE) { backStackEntry ->
            // Scope the ViewModel to the navigation graph to share it between screens
            val viewModel: ExpressModeViewModel = hiltViewModel(
                remember(backStackEntry) {
                    navController.getBackStackEntry(EXPRESS_MODE_GRAPH_ROUTE)
                }
            )
            val uiState by viewModel.uiState.collectAsState()

            ExpressModeScreen(
                uiState = uiState,
                onNavigateToResult = {
                    navController.navigate(EXPRESS_MODE_RESULT_ROUTE) {
                        popUpTo(EXPRESS_MODE_ROUTE) {
                            inclusive = true
                        }
                    }
                },
                onBack = onNavigateUp,
                onExitApp = onExitApp
            )
        }

        composable(EXPRESS_MODE_RESULT_ROUTE) { backStackEntry ->
            // Retrieve the shared ViewModel from the graph scope
            val viewModel: ExpressModeViewModel = hiltViewModel(
                remember(backStackEntry) {
                    navController.getBackStackEntry(EXPRESS_MODE_GRAPH_ROUTE)
                }
            )
            val uiState by viewModel.uiState.collectAsState()

            ExpressModeResultScreen(
                uiState = uiState,
                onNavigateToOssLicenses = onNavigateToOssLicenses,
                onExitApp = onExitApp
            )
        }
    }
}
