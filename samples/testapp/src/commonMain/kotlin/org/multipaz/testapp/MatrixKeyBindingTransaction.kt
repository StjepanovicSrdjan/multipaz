package org.multipaz.testapp

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.multipaz.documenttype.TransactionType

/**
 * Transaction type for binding a Matrix cross-signing master key (+ mxid) to a verified
 * PID presentation. EUDIPLO sends a transaction_data entry shaped like:
 *   { "type": "matrix_key_binding", "credential_ids": ["pid"],
 *     "master_key": "<base64>", "mxid": "@user:server" }
 *
 * Registering this is all that's needed for transaction_data_hashes to land in the KB-JWT —
 * that happens generically in OpenID4VP.processTransactions() over the raw bytes of this
 * entry. parseOpenId4VpRequest below just exposes master_key/mxid for logging/inspection.
 */
object MatrixKeyBindingTransaction : TransactionType<MatrixKeyBindingTransaction.Payload>(
    displayName = "Matrix Key Binding",
    identifier = "matrix_key_binding",
) {
    data class Payload(
        val masterKey: String?,
        val mxid: String?,
    )

    @Serializable
    private data class JsonData(
        val type: String,
        val credential_ids: List<String>,
        val master_key: String? = null,
        val mxid: String? = null,
    )

    private val jsonFormat = Json { ignoreUnknownKeys = true }

    override fun parseOpenId4VpRequest(jsonString: String): Payload {
        val data = jsonFormat.decodeFromString<JsonData>(jsonString)
        return Payload(masterKey = data.master_key, mxid = data.mxid)
    }
}