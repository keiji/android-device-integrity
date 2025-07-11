package dev.keiji.deviceintegrity.ui.main.playintegrity

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.keiji.deviceintegrity.R

@Composable
fun DeviceIntegrityResults(
    deviceRecognitionVerdict: List<String>
) {
    val integrityLevels = listOf(
        "MEETS_STRONG_INTEGRITY",
        "MEETS_DEVICE_INTEGRITY",
        "MEETS_BASIC_INTEGRITY"
    )

    Column(modifier = Modifier.padding(vertical = 8.dp)) {
        Text(
            text = "Device Integrity",
            fontSize = 18.sp, // Slightly larger font size
            modifier = Modifier.padding(bottom = 4.dp)
        )

        integrityLevels.forEach { level ->
            val hasLevel = deviceRecognitionVerdict.contains(level)
            val iconRes = if (hasLevel) R.drawable.ic_shield_fill else R.drawable.ic_gpp_bad
            val text = level.replace("_", " ").lowercase().replaceFirstChar { it.uppercase() }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    painter = painterResource(id = iconRes),
                    contentDescription = text,
                    modifier = Modifier.size(28.dp) // Slightly larger icon size
                )
                Text(
                    text = text,
                    fontSize = 16.sp, // Slightly larger font size
                    modifier = Modifier.padding(start = 8.dp)
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
        }
    }
}
