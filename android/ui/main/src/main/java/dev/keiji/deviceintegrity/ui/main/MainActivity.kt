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
import androidx.compose.ui.res.stringResource
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
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.platform.LocalContext
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.keiji.deviceintegrity.provider.contract.AppInfoProvider
import dev.keiji.deviceintegrity.ui.main.settings.SettingsUiEvent
import dev.keiji.deviceintegrity.ui.main.settings.SettingsViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.keiji.deviceintegrity.ui.nav.contract.AgreementNavigator
import dev.keiji.deviceintegrity.ui.nav.contract.LicenseNavigator
import timber.log.Timber
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject
    lateinit var licenseNavigator: LicenseNavigator

    @Inject
    lateinit var agreementNavigator: AgreementNavigator

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
                agreementNavigator = agreementNavigator,
                onFinishActivity = { finish() }
            )
        }
    }
}

@Composable
fun DeviceIntegrityApp(
    mainViewModel: MainViewModel,
    licenseNavigator: LicenseNavigator,
    agreementNavigator: AgreementNavigator,
    onFinishActivity: () -> Unit
) {
    DeviceIntegrityTheme {
        val navController = rememberNavController()
        val context = LocalContext.current
        val isAgreed by mainViewModel.isAgreed.collectAsStateWithLifecycle()

        val agreementLauncher = rememberLauncherForActivityResult(
            contract = ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == android.app.Activity.RESULT_OK) {
                mainViewModel.setAgreed(true)
            } else {
                onFinishActivity()
            }
        }

        // The outer if condition was removed as per user request.
        // The LaunchedEffect will now run based on isAgreed state regardless of isDebugBuild.
        LaunchedEffect(Unit) {
            if (!mainViewModel.isAgreed.value) { // Avoid re-launching if already agreed during recomposition
                val intent = agreementNavigator.newIntent(context)
                agreementLauncher.launch(intent)
            }
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
                                    contentDescription = stringResource(id = screen.label)
                                )
                            },
                            label = { Text(stringResource(id = screen.label)) },
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
