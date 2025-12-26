package dev.keiji.deviceintegrity.ui.main

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.material3.LocalContentColor
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import dagger.hilt.android.AndroidEntryPoint
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.ui.keyattestation.keyAttestationScreen
import dev.keiji.deviceintegrity.ui.playintegrity.ClassicPlayIntegrityViewModel
import dev.keiji.deviceintegrity.ui.playintegrity.PlayIntegrityScreen
import dev.keiji.deviceintegrity.ui.playintegrity.StandardPlayIntegrityViewModel
import dev.keiji.deviceintegrity.ui.menu.SettingsScreen
import dev.keiji.deviceintegrity.ui.menu.SettingsUiEvent
import dev.keiji.deviceintegrity.ui.menu.SettingsViewModel
import dev.keiji.deviceintegrity.ui.nav.contract.AppScreen
import dev.keiji.deviceintegrity.ui.nav.contract.LicenseNavigator
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme
import timber.log.Timber
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject
    lateinit var licenseNavigator: LicenseNavigator

    @Inject
    lateinit var appInfoProvider: AppInfoProvider

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        Timber.d("MainActivity onCreate")

        setContent {
            val mainViewModel: MainViewModel = viewModel()
            DeviceIntegrityApp(
                mainViewModel = mainViewModel,
                licenseNavigator = licenseNavigator,
                onFinishActivity = { finish() }
            )
        }
    }
}

@Composable
fun DeviceIntegrityApp(
    mainViewModel: MainViewModel,
    licenseNavigator: LicenseNavigator,
    onFinishActivity: () -> Unit
) {
    DeviceIntegrityTheme {
        val navController = rememberNavController()
        val context = LocalContext.current
        val uiState by mainViewModel.uiState.collectAsStateWithLifecycle()

        Scaffold(
            modifier = Modifier.fillMaxSize(),
            bottomBar = {
                NavigationBar {
                    val navBackStackEntry by navController.currentBackStackEntryAsState()
                    val currentDestination = navBackStackEntry?.destination

                    uiState.bottomNavigationItems.forEach { item ->
                        val selected =
                            currentDestination?.hierarchy?.any { it.route == item.screen.route } == true
                        val isKeyAttestationScreen = item.screen is AppScreen.KeyAttestation
                        val isEnabled = if (isKeyAttestationScreen) {
                            uiState.isKeyAttestationSupported
                        } else {
                            true
                        }

                        NavigationBarItem(
                            icon = {
                                val iconTint = if (isEnabled) {
                                    LocalContentColor.current
                                } else {
                                    LocalContentColor.current.copy(alpha = 0.38f)
                                }
                                Icon(
                                    painter = androidx.compose.ui.res.painterResource(id = item.icon),
                                    contentDescription = stringResource(id = item.label),
                                    tint = iconTint
                                )
                            },
                            label = { Text(stringResource(id = item.label)) },
                            selected = selected,
                            onClick = {
                                navController.navigate(item.screen.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            }
                        )
                    }
                }
            }
        ) { innerPadding ->
            NavHost(
                navController = navController,
                startDestination = AppScreen.PlayIntegrity.route,
                modifier = Modifier.padding(innerPadding)
            ) {
                composable(AppScreen.PlayIntegrity.route) {
                    val classicViewModel: ClassicPlayIntegrityViewModel = hiltViewModel()
                    val standardViewModel: StandardPlayIntegrityViewModel = hiltViewModel()
                    val classicUiState by classicViewModel.uiState.collectAsStateWithLifecycle()
                    val standardUiState by standardViewModel.uiState.collectAsStateWithLifecycle()

                    PlayIntegrityScreen(
                        classicUiState = classicUiState,
                        standardUiState = standardUiState,
                        onClassicFetchNonce = { classicViewModel.fetchNonce() },
                        onClassicRequestToken = { classicViewModel.fetchIntegrityToken() },
                        onClassicRequestVerify = { classicViewModel.verifyToken() },
                        onStandardContentBindingChange = { standardViewModel.updateContentBinding(it) },
                        onStandardRequestToken = { standardViewModel.fetchIntegrityToken() },
                        onStandardRequestVerify = { standardViewModel.verifyToken() }
                    )
                }
                keyAttestationScreen()
                composable(AppScreen.Menu.route) {
                    val viewModel: SettingsViewModel = hiltViewModel()
                    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
                    val context = LocalContext.current

                    LaunchedEffect(viewModel.eventFlow) {
                        viewModel.eventFlow.collect { event ->
                            when (event) {
                                is SettingsUiEvent.OpenUrl -> {
                                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(event.url))
                                    context.startActivity(intent)
                                }
                            }
                        }
                    }

                    SettingsScreen(
                        uiState = uiState,
                        onNavigateToOssLicenses = {
                            context.startActivity(licenseNavigator.newIntent(context))
                        },
                        onNavigateToDeveloperInfo = { viewModel.openSupportSiteUrl() },
                        onNavigateToPrivacyPolicy = { viewModel.openPrivacyPolicyUrl() }
                    )
                }
            }
        }
    }
}
