# OWASP Compliance Check Report

This document checks the compliance of the Key Attestation session management with the OWASP Session Management Cheat Sheet.

## Session ID Properties

| Property | Recommendation | Implementation |
| --- | --- | --- |
| Session ID Name Fingerprinting | The name used by the session ID should not be extremely descriptive nor offer unnecessary details about the purpose and meaning of the ID. | The session ID name is `session_id`, which is a generic name. |
| Session ID Entropy | Session identifiers must have at least 64 bits of entropy to prevent brute-force session guessing attacks. | The session ID is a UUIDv4, which has 122 bits of entropy. |
| Session ID Length | The session ID must be long enough to encode sufficient entropy, preventing brute force attacks where an attacker guesses valid session IDs. | The session ID is a UUIDv4, which is 36 characters long (including hyphens). This is long enough to prevent brute force attacks. |
| Session ID Content (or Value) | The session ID content (or value) must be meaningless to prevent information disclosure attacks. | The session ID is a UUIDv4, which is a random value and does not contain any sensitive information. |

## Session Management Implementation

| Property | Recommendation | Implementation |
| --- | --- | --- |
| Built-in Session Management Implementations | It is recommended to use these built-in frameworks versus building a home made one from scratch. | The session management is implemented using the Flask framework and Google Cloud Datastore. |
| Used vs. Accepted Session ID Exchange Mechanisms | A web application should make use of cookies for session ID exchange management. | The session ID is exchanged in the JSON response body, not in cookies. |
| Transport Layer Security | In order to protect the session ID exchange from active eavesdropping and passive disclosure in the network traffic, it is essential to use an encrypted HTTPS (TLS) connection for the entire web session. | The entire communication is over HTTPS. |

## Conclusion

The current implementation of session management in the Key Attestation process is compliant with most of the recommendations in the OWASP Session Management Cheat Sheet. The session ID is generated on the server, has enough entropy and length, and its value is meaningless. The communication is over HTTPS, which protects the session ID from eavesdropping.

The only recommendation that is not followed is the use of cookies for session ID exchange. However, since the session ID is only used for a single request-response cycle and is not stored on the client, the risk of not using cookies is low.
