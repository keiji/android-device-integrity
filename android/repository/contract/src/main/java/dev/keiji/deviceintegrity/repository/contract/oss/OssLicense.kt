package dev.keiji.deviceintegrity.repository.contract.oss

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class OssLicense(
    @SerialName("settings")
    val settings: String?,

    @SerialName("pom_list")
    val pomList: List<PomInfo>
)
