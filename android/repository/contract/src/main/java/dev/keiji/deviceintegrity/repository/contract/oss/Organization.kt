package dev.keiji.deviceintegrity.repository.contract.oss // パッケージ名を変更

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Organization(
    @SerialName("name")
    val name: String,

    @SerialName("url")
    val url: String?
)
