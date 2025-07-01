package dev.keiji.deviceintegrity.ui.license

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.license.R
import dev.keiji.deviceintegrity.ui.theme.DeviceIntegrityTheme

@Composable
fun LicenseList( // Renamed from LicenseScreen
    licenses: List<LicenseInfo>,
    contentPadding: PaddingValues = PaddingValues(0.dp)
) {
    val context = LocalContext.current

    LazyColumn(
        modifier = Modifier.padding(contentPadding)
    ) {
        items(licenses) { license ->
            LicenseItem(
                licenseInfo = license,
                onClick = {
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(license.licenseUrl))
                    context.startActivity(intent)
                }
            )
        }
    }
}

@Composable
fun LicenseItem(
    licenseInfo: LicenseInfo,
    onClick: () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp
    ) {
        Column(
            modifier = Modifier
                .clickable(onClick = onClick)
                .padding(16.dp)
        ) {
            Text(
                text = licenseInfo.softwareName,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.license_item_license_label, licenseInfo.licenseName),
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.license_item_copyright_label, licenseInfo.copyrightHolder),
                style = MaterialTheme.typography.bodyMedium
            )
            licenseInfo.licenseUrl?.also { licenseUrl ->
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = licenseUrl,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.clickable(onClick = onClick)
                )
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun LicenseListPreview() { // Renamed from LicenseScreenPreview
    DeviceIntegrityTheme {
        val previewLicenses = listOf(
            LicenseInfo("Preview Lib 1", "MIT", "Dev", "url1"),
            LicenseInfo("Preview Lib 2", "Apache 2.0", "Another Dev", "url2")
        )
        LicenseList( // Renamed from LicenseScreen
            licenses = previewLicenses
        )
    }
}

@Preview(showBackground = true)
@Composable
fun LicenseItemPreview() {
    DeviceIntegrityTheme {
        LicenseItem(
            licenseInfo = LicenseInfo(
                "Sample Software",
                "MIT License",
                "Awesome Developer",
                "https://opensource.org/licenses/MIT"
            ),
            onClick = {}
        )
    }
}
