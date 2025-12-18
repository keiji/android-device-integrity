package dev.keiji.deviceintegrity.ui.main

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

@Composable
fun StartupScreen(
    onCheckImmediately: () -> Unit,
    onConfigureDetails: () -> Unit,
    onExitApp: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.fillMaxSize()
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Button(
                onClick = onCheckImmediately,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp)
            ) {
                Text(text = stringResource(id = R.string.startup_action_check_immediately))
            }

            Button(
                onClick = onConfigureDetails,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp)
            ) {
                Text(text = stringResource(id = R.string.startup_action_configure_details))
            }

            Button(
                onClick = onExitApp,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = stringResource(id = R.string.startup_action_exit_app))
            }
        }
    }
}
