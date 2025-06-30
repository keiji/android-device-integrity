package dev.keiji.deviceintegrity.repository.contract.oss

interface OssLicenseRepository {
    suspend fun loadLicenses(): List<PomInfo>
}
