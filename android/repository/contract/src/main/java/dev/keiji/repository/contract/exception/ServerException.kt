package dev.keiji.repository.contract.exception

import java.io.IOException

/**
 * Represents an error that occurred when communicating with the server.
 * @param errorCode The HTTP error code.
 * @param errorMessage A descriptive error message from the server, if available.
 * @param cause The original exception that caused this error, if any.
 */
class ServerException(
    val errorCode: Int? = null,
    val errorMessage: String? = null,
    cause: Throwable? = null
) : IOException(errorMessage, cause)
