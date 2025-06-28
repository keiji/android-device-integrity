package dev.keiji.deviceintegrity.ui.agreement

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

class AgreementActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AgreementScreen(
                        onAgree = {
                            setResult(Activity.RESULT_OK)
                            finish()
                        },
                        onDisagree = {
                            setResult(Activity.RESULT_CANCELED)
                            finish()
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun AgreementScreen(
    onAgree: () -> Unit,
    onDisagree: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = "利用規約に同意しますか？") // Replace with your actual agreement text
        Spacer(modifier = Modifier.height(24.dp))
        Button(onClick = onAgree) {
            Text("同意する")
        }
        Spacer(modifier = Modifier.height(8.dp))
        Button(onClick = onDisagree) {
            Text("同意しない")
        }
    }
}

@Preview(showBackground = true)
@Composable
fun AgreementScreenPreview() {
    MaterialTheme {
        AgreementScreen(onAgree = {}, onDisagree = {})
    }
}
