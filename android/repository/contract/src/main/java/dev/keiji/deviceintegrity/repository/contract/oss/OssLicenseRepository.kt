package dev.keiji.deviceintegrity.repository.contract.oss

// Assuming PomInfo is defined in the same package or imported correctly
// import dev.keiji.deviceintegrity.repository.contract.oss.PomInfo

interface OssLicenseRepository {
    suspend fun loadLicenses(): List<PomInfo>
}
