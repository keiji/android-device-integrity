package dev.keiji.deviceintegrity.ui.license

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
// import androidx.compose.foundation.layout.padding // No longer directly used here
// import androidx.compose.foundation.rememberScrollState // No longer directly used here
// import androidx.compose.foundation.verticalScroll // No longer directly used here
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
// import androidx.compose.ui.unit.dp // No longer directly used here
import androidx.hilt.navigation.compose.hiltViewModel
import dagger.hilt.android.AndroidEntryPoint
import dev.keiji.deviceintegrity.ui.license.R
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

@AndroidEntryPoint
class LicenseActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            DeviceIntegrityTheme {
                LicenseView( // Renamed from LicenseContent
                    onClose = { finish() }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LicenseView( // Renamed from LicenseContent
    onClose: () -> Unit,
    viewModel: LicenseViewModel = hiltViewModel()
) {
    val scrollBehavior = TopAppBarDefaults.enterAlwaysScrollBehavior(rememberTopAppBarState())

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            TopAppBar(
                title = { Text(text = stringResource(id = R.string.open_source_licenses)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = MaterialTheme.colorScheme.onPrimary,
                ),
                navigationIcon = {
                    IconButton(onClick = onClose) {
                        Icon(
                            painter = painterResource(id = R.drawable.ic_close),
                            contentDescription = "Close",
                            tint = MaterialTheme.colorScheme.onPrimary
                        )
                    }
                },
                scrollBehavior = scrollBehavior
            )
        }
    ) { paddingValues ->
        val licenses by viewModel.licenses.collectAsState()

        // Log to confirm licenses are collected
        Log.d("LicenseActivity", "Collected licenses: ${licenses.size} items")

        LicenseScreen( // Use the Composable from LicenseScreen.kt
            licenses = licenses,
            contentPadding = paddingValues
        )
    }
}
