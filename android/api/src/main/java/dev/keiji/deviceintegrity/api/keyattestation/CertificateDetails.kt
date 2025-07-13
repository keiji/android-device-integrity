package dev.keiji.deviceintegrity.api.keyattestation

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CertificateDetails(
    @SerialName("name")
    val name: String? = null,
    @SerialName("serial_number")
    val serialNumber: String? = null,
    @SerialName("valid_from")
    val validFrom: String? = null,
    @SerialName("valid_to")
    val validTo: String? = null,
    @SerialName("signature_type_sn")
    val signatureTypeSn: String? = null,
    @SerialName("signature_type_ln")
    val signatureTypeLn: String? = null,
    @SerialName("subject_key_identifier")
    val subjectKeyIdentifier: String? = null,
    @SerialName("authority_key_identifier")
    val authorityKeyIdentifier: String? = null,
    @SerialName("key_usage")
    val keyUsage: KeyUsage? = null,
)

@Serializable
data class KeyUsage(
    @SerialName("digital_signature")
    val digitalSignature: Boolean,
    @SerialName("content_commitment")
    val contentCommitment: Boolean,
    @SerialName("key_encipherment")
    val keyEncipherment: Boolean,
    @SerialName("data_encipherment")
    val dataEncipherment: Boolean,
    @SerialName("key_agreement")
    val keyAgreement: Boolean,
    @SerialName("key_cert_sign")
    val keyCertSign: Boolean,
    @SerialName("crl_sign")
    val crlSign: Boolean,
    @SerialName("encipher_only")
    val encipherOnly: Boolean,
    @SerialName("decipher_only")
    val decipherOnly: Boolean,
)
