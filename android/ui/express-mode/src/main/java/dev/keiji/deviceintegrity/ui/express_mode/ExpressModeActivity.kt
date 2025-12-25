package dev.keiji.deviceintegrity.ui.express_mode

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.rememberNavController
import dagger.hilt.android.AndroidEntryPoint
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

@AndroidEntryPoint
class ExpressModeActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            DeviceIntegrityTheme {
                val navController = rememberNavController()
                NavHost(
                    navController = navController,
                    startDestination = EXPRESS_MODE_ROUTE
                ) {
                    expressModeScreen(
                        onNavigateUp = {
                            if (!navController.popBackStack()) {
                                finish()
                            }
                        },
                        onExitApp = {
                            finishAffinity()
                        }
                    )
                }
            }
        }
    }
}
