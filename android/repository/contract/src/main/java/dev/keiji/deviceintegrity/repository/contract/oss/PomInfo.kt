package dev.keiji.deviceintegrity.repository.contract.oss

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PomInfo(
    @SerialName("group_id")
    val groupId: String,

    @SerialName("artifact_id")
    val artifactId: String,

    @SerialName("version")
    val version: String,

    @SerialName("name")
    val name: String,

    @SerialName("url")
    val url: String?,

    @SerialName("licenses")
    val licenses: List<License>,

    @SerialName("developers")
    val developers: List<Developer>,

    @SerialName("organization")
    val organization: Organization?,

    @SerialName("dependencies")
    val dependencies: List<String>,

    @SerialName("depth")
    val depth: Int
)
