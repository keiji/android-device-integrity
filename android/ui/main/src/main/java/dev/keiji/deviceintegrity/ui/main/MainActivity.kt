package dev.keiji.deviceintegrity.ui.main

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
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
import androidx.compose.runtime.collectAsState
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
import dev.keiji.deviceintegrity.ui.main.keyattestation.KeyAttestationScreen
import dev.keiji.deviceintegrity.ui.main.keyattestation.KeyAttestationUnsupportedScreen
import dev.keiji.deviceintegrity.ui.main.keyattestation.KeyAttestationViewModel
import dev.keiji.deviceintegrity.ui.main.playintegrity.ClassicPlayIntegrityViewModel
import dev.keiji.deviceintegrity.ui.main.playintegrity.PlayIntegrityScreen
import dev.keiji.deviceintegrity.ui.main.playintegrity.StandardPlayIntegrityViewModel
import dev.keiji.deviceintegrity.ui.main.settings.SettingsScreen
import dev.keiji.deviceintegrity.ui.main.settings.SettingsUiEvent
import dev.keiji.deviceintegrity.ui.main.settings.SettingsViewModel
import dev.keiji.deviceintegrity.ui.nav.contract.AgreementNavigator
import dev.keiji.deviceintegrity.ui.nav.contract.LicenseNavigator
import dev.keiji.deviceintegrity.ui.main.BuildConfig
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme
import timber.log.Timber
import javax.inject.Inject
import dev.keiji.deviceintegrity.ui.main.R

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
        val uiState by mainViewModel.uiState.collectAsState()

        val agreementLauncher = rememberLauncherForActivityResult(
            contract = ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == android.app.Activity.RESULT_OK) {
                mainViewModel.setAgreed(true)
            } else {
                onFinishActivity()
            }
        }

        LaunchedEffect(Unit) {
            if (!mainViewModel.isAgreed.value) {
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

                    uiState.bottomNavigationItems.forEach { screen ->
                        val selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true
                        val isKeyAttestationScreen = screen.route == AppScreen.KeyAttestation.route
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
                                    painter = androidx.compose.ui.res.painterResource(id = screen.icon),
                                    contentDescription = stringResource(id = screen.label),
                                    tint = iconTint
                                )
                            },
                            label = { Text(stringResource(id = screen.label)) },
                            selected = selected,
                            enabled = isEnabled,
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
                    if (uiState.isKeyAttestationSupported) {
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
                                    currentContext.getString(R.string.key_attestation_result_label),
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
                    } else {
                        KeyAttestationUnsupportedScreen()
                    }
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
