package dev.keiji.deviceintegrity.ui.main

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
// Removed Material Icons imports
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource // Added
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.keiji.deviceintegrity.ui.main.R // Import for R.drawable

@Composable
fun InfoItemContent(
    status: String,
    isVerifiedSuccessfully: Boolean,
    infoItems: List<InfoItem>,
    onCopyClick: () -> Unit,
    onShareClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier) {
        Text(
            text = status,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            color = if (status.contains("Failed", ignoreCase = true) || status.contains("Error", ignoreCase = true)) {
                MaterialTheme.colorScheme.error
            } else {
                Color.Unspecified
            },
            style = MaterialTheme.typography.titleMedium
        )

        if (infoItems.isNotEmpty()) {
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            if (isVerifiedSuccessfully) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.End
                ) {
                    IconButton(onClick = onCopyClick) {
                        Icon(
                            painter = painterResource(id = R.drawable.ic_content_copy),
                            contentDescription = "Copy"
                        )
                    }
                    IconButton(onClick = onShareClick) {
                        Icon(
                            painter = painterResource(id = R.drawable.ic_share),
                            contentDescription = "Share"
                        )
                    }
                }
            }

            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(
                    modifier = Modifier
                        .padding(12.dp)
                ) {
                    infoItems.forEachIndexed { index, item ->
                        val textStyle = if (item.isHeader) {
                            MaterialTheme.typography.titleSmall
                        } else {
                            MaterialTheme.typography.bodyMedium
                        }
                        val itemPadding = when (item.indentLevel) {
                            1 -> Modifier.padding(start = 16.dp)
                            2 -> Modifier.padding(start = 32.dp)
                            else -> Modifier
                        }

                        Column(modifier = itemPadding) {
                            if (item.isHeader) {
                                Text(
                                    text = item.label,
                                    style = textStyle,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(top = if (index > 0) 8.dp else 0.dp, bottom = 4.dp)
                                )
                            } else {
                                Row(
                                     modifier = Modifier.padding(vertical = 2.dp)
                                ) {
                                    Text(
                                        text = "${item.label}:",
                                        style = textStyle,
                                        fontWeight = FontWeight.Bold,
                                    )
                                    Text(
                                        text = " ${item.value}",
                                        style = textStyle,
                                    )
                                }
                            }
                        }
                        if (item.isHeader && item.indentLevel == 0 && index < infoItems.lastIndex) {
                            HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))
                        }
                    }
                }
            }
        }
    }
}
