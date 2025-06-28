package dev.keiji.deviceintegrity.ui.main

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import dagger.hilt.android.AndroidEntryPoint
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import dev.keiji.deviceintegrity.ui.main.keyattestation.KeyAttestationScreen
import dev.keiji.deviceintegrity.ui.main.playintegrity.ClassicPlayIntegrityViewModel
import dev.keiji.deviceintegrity.ui.main.playintegrity.PlayIntegrityScreen
import dev.keiji.deviceintegrity.ui.main.playintegrity.StandardPlayIntegrityViewModel
import dev.keiji.deviceintegrity.ui.main.settings.SettingsScreen
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.hilt.navigation.compose.hiltViewModel
import dev.keiji.deviceintegrity.ui.main.settings.SettingsUiEvent
import dev.keiji.deviceintegrity.ui.main.settings.SettingsViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.keiji.deviceintegrity.ui.nav.contract.AgreementNavigator
import dev.keiji.deviceintegrity.ui.nav.contract.ApiEndpointSettingsNavigator
import dev.keiji.deviceintegrity.ui.nav.contract.LicenseNavigator
import timber.log.Timber
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject
    lateinit var apiEndpointSettingsNavigator: ApiEndpointSettingsNavigator

    @Inject
    lateinit var licenseNavigator: LicenseNavigator

    @Inject
    lateinit var agreementNavigator: AgreementNavigator

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        Timber.d("MainActivity onCreate")

        setContent {
            DeviceIntegrityApp(
                apiEndpointSettingsNavigator = apiEndpointSettingsNavigator,
                licenseNavigator = licenseNavigator,
                agreementNavigator = agreementNavigator,
                onFinishActivity = { finish() }
            )
        }
    }
}

@Composable
fun DeviceIntegrityApp(
    apiEndpointSettingsNavigator: ApiEndpointSettingsNavigator,
    licenseNavigator: LicenseNavigator,
    agreementNavigator: AgreementNavigator,
    onFinishActivity: () -> Unit
) {
    DeviceIntegrityTheme {
        val navController = rememberNavController()
        val context = LocalContext.current

        val agreementLauncher = rememberLauncherForActivityResult(
            contract = ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode != android.app.Activity.RESULT_OK) {
                onFinishActivity()
            }
        }

        LaunchedEffect(Unit) {
            val intent = agreementNavigator.newIntent(context)
            agreementLauncher.launch(intent)
        }

        Scaffold(
            modifier = Modifier.fillMaxSize(),
            bottomBar = {
                NavigationBar {
                    val navBackStackEntry by navController.currentBackStackEntryAsState()
                    val currentDestination = navBackStackEntry?.destination
                    bottomNavigationItems.forEach { screen ->
                        NavigationBarItem(
                            icon = {
                                Icon(
                                    painter = androidx.compose.ui.res.painterResource(id = screen.icon),
                                    contentDescription = screen.label
                                )
                            },
                            label = { Text(screen.label) },
                            selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true,
                            onClick = {
                                navController.navigate(screen.route) {
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
                /*
                composable(AppScreen.KeyAttestation.route) {
                    val viewModel: KeyAttestationViewModel = hiltViewModel()
                    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
                    val context = LocalContext.current

                    LaunchedEffect(viewModel.eventFlow) {
                        viewModel.eventFlow.collect { event ->
                            when (event) {
                                is KeyAttestationUiEvent.ShowToast -> {
                                    Toast.makeText(context, event.message, Toast.LENGTH_SHORT).show()
                                }
                            }
                        }
                    }

                    KeyAttestationScreen(
                        uiState = uiState,
                        onNonceChange = viewModel::updateNonce,
                        onSubmit = viewModel::submit
                    )
                }
                */
                composable(AppScreen.Settings.route) {
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

                    val apiSettingsLauncher = rememberLauncherForActivityResult(
                        contract = apiEndpointSettingsNavigator.contract(),
                        onResult = { /* No result is expected, but can handle if needed */ }
                    )

                    SettingsScreen(
                        uiState = uiState,
                        onNavigateToOssLicenses = {
                            context.startActivity(licenseNavigator.newIntent(context))
                        },
                        onNavigateToApiSettings = { apiSettingsLauncher.launch(Unit) },
                        onNavigateToDeveloperInfo = { viewModel.openSupportSiteUrl() },
                        onNavigateToPrivacyPolicy = { viewModel.openPrivacyPolicyUrl() }
                    )
                }
            }
        }
    }
}
