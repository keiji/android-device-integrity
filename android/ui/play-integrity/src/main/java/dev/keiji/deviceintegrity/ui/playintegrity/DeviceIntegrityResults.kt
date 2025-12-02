package dev.keiji.deviceintegrity.ui.playintegrity

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun DeviceIntegrityResults(
    deviceRecognitionVerdict: List<String>
) {
    val integrityLevels = listOf(
        DeviceIntegrityVerdict.MEETS_STRONG_INTEGRITY,
        DeviceIntegrityVerdict.MEETS_DEVICE_INTEGRITY,
        DeviceIntegrityVerdict.MEETS_VIRTUAL_INTEGRITY,
        DeviceIntegrityVerdict.MEETS_BASIC_INTEGRITY
    )

    Column(modifier = Modifier.padding(vertical = 8.dp)) {
        Text(
            text = "Device Integrity",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(bottom = 4.dp)
        )

        Spacer(modifier = Modifier.height(8.dp))

        integrityLevels.forEach { level ->
            val text = level.split("_").joinToString(" ") { it ->
                it.lowercase().replaceFirstChar { it.uppercase() }
            }
            val hasLevel = deviceRecognitionVerdict.contains(level)
            val iconRes =
                if (hasLevel) R.drawable.shield_48dp_000000_fill1_wght400_grad0_opsz48 else R.drawable.gpp_bad_48dp_000000_fill0_wght400_grad0_opsz48
            val alpha = if (hasLevel) 1f else 0.5f

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(start = 4.dp)
            ) {
                Icon(
                    painter = painterResource(id = iconRes),
                    contentDescription = text,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .alpha(alpha)
                        .size(36.dp)
                )
                Text(
                    text = text,
                    fontSize = 20.sp,
                    modifier = Modifier
                        .alpha(alpha)
                        .padding(start = 8.dp)
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}
