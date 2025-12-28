package dev.keiji.deviceintegrity.ui.express_mode

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.rememberNavController
import dagger.hilt.android.AndroidEntryPoint
import dev.keiji.deviceintegrity.ui.nav.contract.LicenseNavigator
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme
import javax.inject.Inject

@AndroidEntryPoint
class ExpressModeActivity : ComponentActivity() {

    @Inject
    lateinit var licenseNavigator: LicenseNavigator

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val context = LocalContext.current
            DeviceIntegrityTheme {
                val navController = rememberNavController()
                NavHost(
                    navController = navController,
                    startDestination = EXPRESS_MODE_GRAPH_ROUTE
                ) {
                    expressModeScreen(
                        navController = navController,
                        onShareClick = { textToShare ->
                            val sendIntent: Intent = Intent().apply {
                                action = Intent.ACTION_SEND
                                putExtra(Intent.EXTRA_TEXT, textToShare)
                                type = "text/plain"
                            }
                            val shareIntent = Intent.createChooser(sendIntent, null)
                            startActivity(shareIntent)
                        },
                        onNavigateToOssLicenses = {
                            startActivity(licenseNavigator.newIntent(context))
                        },
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
