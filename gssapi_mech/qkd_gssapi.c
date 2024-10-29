/* qkd_gssapi.c */

/* Include necessary headers */
#include <gssapi/gssapi.h>
#include "qkd.h" 
#include <curl/curl.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Define constants and types */
#define QKD_GSS_MECH_OID_LENGTH 9
static gss_OID_desc QKD_GSS_MECH_OID_DESC = {
    QKD_GSS_MECH_OID_LENGTH,
    (void *) "\x2b\x06\x01\x04\x01\x82\x37\x14\x02" // Example OID: 1.3.6.1.4.1.12345.2
};
static gss_OID QKD_GSS_MECH_OID = &QKD_GSS_MECH_OID_DESC;

#define KEY_LENGTH 32          // 256 bits
#define KEY_SEGMENT_LENGTH 16  // 128 bits
#define KEY_ID_LENGTH 16       // Assume 128-bit key IDs

typedef struct {
    uint8_t formed_session_key[KEY_LENGTH];
} QKD_Context;

/* Token structures */
typedef struct {
    uint8_t key_id1[KEY_ID_LENGTH];
} QKD_InitToken;

/* Function prototypes */
OM_uint32 gss_acquire_cred(
    OM_uint32 *minor_status,
    gss_name_t desired_name,
    OM_uint32 time_req,
    gss_OID_set desired_mechs,
    gss_cred_usage_t cred_usage,
    gss_cred_id_t *output_cred_handle,
    gss_OID_set *actual_mechs,
    OM_uint32 *time_rec
);

OM_uint32 gss_release_cred(
    OM_uint32 *minor_status,
    gss_cred_id_t *cred_handle
);

OM_uint32 gss_init_sec_context(
    OM_uint32 *minor_status,
    gss_cred_id_t claimant_cred_handle,
    gss_ctx_id_t *context_handle,
    gss_name_t target_name,
    gss_OID mech_type,
    OM_uint32 req_flags,
    OM_uint32 time_req,
    gss_channel_bindings_t input_chan_bindings,
    gss_buffer_t input_token,
    gss_OID *actual_mech_type,
    gss_buffer_t output_token,
    OM_uint32 *ret_flags,
    OM_uint32 *time_rec
);

OM_uint32 gss_accept_sec_context(
    OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle,
    gss_cred_id_t acceptor_cred_handle,
    gss_buffer_t input_token,
    gss_channel_bindings_t input_chan_bindings,
    gss_name_t *src_name,
    gss_OID *mech_type,
    gss_buffer_t output_token,
    OM_uint32 *ret_flags,
    OM_uint32 *time_rec,
    gss_cred_id_t *delegated_cred_handle
);

OM_uint32 gss_delete_sec_context(
    OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle,
    gss_buffer_t output_token
);

OM_uint32 gss_display_status(
    OM_uint32 *minor_status,
    OM_uint32 status_value,
    int status_type,
    gss_OID mech_type,
    OM_uint32 *message_context,
    gss_buffer_t status_string
);

OM_uint32 gss_release_buffer(
    OM_uint32 *minor_status,
    gss_buffer_t buffer
);

/* GSSAPI function implementations */

OM_uint32 gss_acquire_cred(
    OM_uint32 *minor_status,
    gss_name_t desired_name,
    OM_uint32 time_req,
    gss_OID_set desired_mechs,
    gss_cred_usage_t cred_usage,
    gss_cred_id_t *output_cred_handle,
    gss_OID_set *actual_mechs,
    OM_uint32 *time_rec
) {
    if (minor_status == NULL || output_cred_handle == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    *minor_status = 0;

    // Allocate and initialize the credential structure
    QKD_Credential *cred = (QKD_Credential *)malloc(sizeof(QKD_Credential));
    if (cred == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    // Initialize fields to NULL
    memset(cred, 0, sizeof(QKD_Credential));

    // This determines on which URL the QKD Get Key request will be made.
    const char *env_client_name = "QKD_CLIENT_NAME";
    char *env_client_value = getenv(env_client_name);

    if (env_client_value != NULL) {
        cred->principal_name = strdup(env_client_value);
    } else {
        fprintf(stderr, "Environment variable %s is not set.\n", env_client_name);
        free(cred);
        return GSS_S_FAILURE;
    }

    *output_cred_handle = (gss_cred_id_t)cred;

    if (actual_mechs != NULL) {
        *actual_mechs = GSS_C_NO_OID_SET;
    }

    if (time_rec != NULL) {
        *time_rec = GSS_C_INDEFINITE;
    }

    return GSS_S_COMPLETE;
}

OM_uint32 gss_release_cred(
    OM_uint32 *minor_status,
    gss_cred_id_t *cred_handle
) {
    if (minor_status == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    *minor_status = 0;

    if (cred_handle == NULL || *cred_handle == GSS_C_NO_CREDENTIAL) {
        return GSS_S_COMPLETE;
    }

    QKD_Credential *cred = (QKD_Credential *)(*cred_handle);

    // Free any allocated memory within the credential
    if (cred->principal_name != NULL) {
        memset(cred->principal_name, 0, strlen(cred->principal_name));
        free(cred->principal_name);
    }

    // Securely erase and free the credential structure
    memset(cred, 0, sizeof(QKD_Credential));
    free(cred);

    *cred_handle = GSS_C_NO_CREDENTIAL;

    return GSS_S_COMPLETE;
}

OM_uint32 gss_init_sec_context(
    OM_uint32 *minor_status,
    gss_cred_id_t claimant_cred_handle,
    gss_ctx_id_t *context_handle,
    gss_name_t target_name,
    gss_OID mech_type,
    OM_uint32 req_flags,
    OM_uint32 time_req,
    gss_channel_bindings_t input_chan_bindings,
    gss_buffer_t input_token,
    gss_OID *actual_mech_type,
    gss_buffer_t output_token,
    OM_uint32 *ret_flags,
    OM_uint32 *time_rec
) {
    if (minor_status == NULL || output_token == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    *minor_status = 0;

    if (context_handle == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    if (mech_type != NULL) {
        *mech_type = *QKD_GSS_MECH_OID; // Assign the OID
    }

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
        /* Initial call to establish context */

        /* Step 1: Retrieve Keys and Key IDs from QKD Device */
        QKD_Key key1;
        QKD_Key key2;
        QKD_Key key3;

        QKD_Credential *cred = (QKD_Credential *)claimant_cred_handle;
        if (qkd_get_key(cred, &key1) != 0) {
            // Handle error
            return GSS_S_FAILURE;
        }

        if (qkd_get_key(cred, &key2) != 0) {
            // Handle error
            return GSS_S_FAILURE;
        }

        if (qkd_get_key(cred, &key3) != 0) {
            // Handle error
            return GSS_S_FAILURE;
        }

        /* Step 2: Prepare the Initial Token */
        QKD_InitToken init_token;
        memcpy(init_token.key_id1, key1.key_id, KEY_ID_LENGTH);

        /* Step 3: Serialize the Token */
        output_token->length = sizeof(QKD_InitToken);
        output_token->value = malloc(output_token->length);
        if (output_token->value == NULL) {
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        memcpy(output_token->value, &init_token, output_token->length);

        /* Step 4: Store Key in Security Context */
        QKD_Context *ctx = (QKD_Context *)malloc(sizeof(QKD_Context));
        if (ctx == NULL) {
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        memcpy(&ctx->formed_session_key, &key1, KEY_LENGTH);

        *context_handle = (gss_ctx_id_t)ctx;
    }
    return GSS_S_CONTINUE_NEEDED;
}

OM_uint32 gss_accept_sec_context(
    OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle,
    gss_cred_id_t acceptor_cred_handle,
    gss_buffer_t input_token,
    gss_channel_bindings_t input_chan_bindings,
    gss_name_t *src_name,
    gss_OID *mech_type,
    gss_buffer_t output_token,
    OM_uint32 *ret_flags,
    OM_uint32 *time_rec,
    gss_cred_id_t *delegated_cred_handle
) {
    if (minor_status == NULL || input_token == NULL || output_token == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    *minor_status = 0;

    if (context_handle == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    if (mech_type != NULL) {
        *mech_type = QKD_GSS_MECH_OID; // Assign the OID
    }

    /* Step 1: Deserialize the Input Token */
    if (input_token->length != sizeof(QKD_InitToken)) {
        return GSS_S_DEFECTIVE_TOKEN;
    }
    QKD_InitToken init_token;
    memcpy(&init_token, input_token->value, input_token->length);

    QKD_Credential *cred = (QKD_Credential *)acceptor_cred_handle;

    /* Step 2: Retrieve Key from QKD Device Using Key ID */
    QKD_Key key1;
    if (qkd_get_key_by_id(cred, init_token.key_id1, &key1) != 0) {
        // Handle error
        fprintf(stderr, "Failed to retrieve key by ID from QKD device\n");
        return GSS_S_FAILURE;
    }
    /* Step 3: Store Key in Security Context */
    QKD_Context *ctx = (QKD_Context *)malloc(sizeof(QKD_Context));
    if (ctx == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(&ctx->formed_session_key, &key1, KEY_LENGTH);

    *context_handle = (gss_ctx_id_t)ctx;

    return GSS_S_COMPLETE;
}

OM_uint32 gss_delete_sec_context(
    OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle,
    gss_buffer_t output_token
) {
    if (minor_status == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    *minor_status = 0;

    if (context_handle && *context_handle) {
        QKD_Context *ctx = (QKD_Context *)(*context_handle);
        /* Securely erase key material */
        memset(ctx, 0, sizeof(QKD_Context));
        free(ctx);
        *context_handle = GSS_C_NO_CONTEXT;
    }

    if (output_token != NULL) {
        output_token->length = 0;
        output_token->value = NULL;
    }

    return GSS_S_COMPLETE;
}

OM_uint32 gss_display_status(
    OM_uint32 *minor_status,
    OM_uint32 status_value,
    int status_type,
    gss_OID mech_type,
    OM_uint32 *message_context,
    gss_buffer_t status_string
) {
    if (minor_status == NULL || status_string == NULL || message_context == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    if (mech_type != NULL) {
        *mech_type = *QKD_GSS_MECH_OID; // Assign the OID
    }

    *minor_status = 0;
    *message_context = 0; // Single-part messages

    const char *msg = NULL;

    if (status_type == GSS_C_GSS_CODE) {
        // Interpret GSSAPI major status codes
        switch (status_value) {
            case GSS_S_COMPLETE:
                msg = "No error";
                break;
            case GSS_S_BAD_MECH:
                msg = "Unsupported mechanism requested";
                break;
            case GSS_S_BAD_NAME:
                msg = "Invalid name provided";
                break;
            case GSS_S_FAILURE:
                msg = "General failure";
                break;
            case GSS_S_DEFECTIVE_TOKEN:
                msg = "Defective token";
                break;
            default:
                msg = "Unknown GSSAPI error";
                break;
        }
    } else if (status_type == GSS_C_MECH_CODE) {
        // Interpret mechanism-specific minor status codes
        switch (status_value) {
            case 0:
                msg = "No error";
                break;
            case 1:
                msg = "QKD device communication error";
                break;
            case 2:
                msg = "Key synchronization failed";
                break;
            case 3:
                msg = "Invalid token received";
                break;
            default:
                msg = "Unknown mechanism-specific error";
                break;
        }
    } else {
        // Invalid status_type
        return GSS_S_FAILURE;
    }

    // Allocate and set the status string
    status_string->length = strlen(msg);
    status_string->value = malloc(status_string->length + 1);
    if (status_string->value == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    strcpy((char *)status_string->value, msg);

    return GSS_S_COMPLETE;
}

OM_uint32 gss_release_buffer(
    OM_uint32 *minor_status,
    gss_buffer_t buffer
) {
    if (minor_status == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    *minor_status = 0;

    if (buffer == GSS_C_NO_BUFFER || buffer->value == NULL) {
        return GSS_S_COMPLETE;
    }

    // Securely erase and free the buffer memory
    memset(buffer->value, 0, buffer->length);
    free(buffer->value);

    // Reset the buffer fields
    buffer->value = NULL;
    buffer->length = 0;

    return GSS_S_COMPLETE;
}

OM_uint32 gss_pseudo_random(
    OM_uint32 *minor_status,
    gss_ctx_id_t context_handle,
    int prf_key,
    const gss_buffer_t prf_in,
    ssize_t desired_output_len,
    gss_buffer_t prf_out
) {
    if (minor_status == NULL || context_handle == GSS_C_NO_CONTEXT || prf_out == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    *minor_status = 0;

    // Retrieve the session key from the context
    QKD_Context *context = (QKD_Context *)context_handle;
    uint8_t *session_key = context->formed_session_key; // Assume 32 bytes (256 bits)
    
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;
    OSSL_PARAM params[5], *p = params;
    unsigned char *output = NULL;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        *minor_status = GSS_S_FAILURE;
        return GSS_S_FAILURE;
    }

    kdf_ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kdf_ctx == NULL) {
        *minor_status = GSS_S_FAILURE;
        return GSS_S_FAILURE;
    }

    // Set up the parameters for HKDF with SHA256
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string("salt", NULL, 0); // Optional salt (can be NULL)
    *p++ = OSSL_PARAM_construct_octet_string("key", session_key, KEY_LENGTH);
    if (prf_in != GSS_C_NO_BUFFER && prf_in->length > 0) {
        *p++ = OSSL_PARAM_construct_octet_string("info", prf_in->value, prf_in->length);
    } else {
        *p++ = OSSL_PARAM_construct_octet_string("info", NULL, 0);
    }
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_CTX_set_params(kdf_ctx, params) <= 0) {
        EVP_KDF_CTX_free(kdf_ctx);
        *minor_status = GSS_S_FAILURE;
        return GSS_S_FAILURE;
    }

    // Allocate output buffer
    output = (uint8_t *)malloc(desired_output_len);
    if (output == NULL) {
        EVP_KDF_CTX_free(kdf_ctx);
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    // Derive the keying material
    if (EVP_KDF_derive(kdf_ctx, output, desired_output_len, p) <= 0) {
        EVP_KDF_CTX_free(kdf_ctx);
        free(output);
        *minor_status = GSS_S_FAILURE;
        return GSS_S_FAILURE;
    }

    EVP_KDF_CTX_free(kdf_ctx);

    // Set the output buffer
    prf_out->length = desired_output_len;
    prf_out->value = output;

    return GSS_S_COMPLETE;
}
