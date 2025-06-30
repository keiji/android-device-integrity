package dev.keiji.deviceintegrity.repository.contract.oss // パッケージ名を変更

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class OssLicense(
    @SerialName("settings")
    val settings: String?, // Assuming settings is a String?, adjust if it's a complex object

    @SerialName("pom_list")
    val pomList: List<PomInfo>
)
