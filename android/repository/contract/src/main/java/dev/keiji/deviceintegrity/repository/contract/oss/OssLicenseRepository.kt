package dev.keiji.deviceintegrity.repository.contract.oss

// PomInfo is in the same package
// import dev.keiji.deviceintegrity.repository.contract.oss.PomInfo

interface OssLicenseRepository {
    suspend fun loadLicenses(): List<PomInfo>
}
