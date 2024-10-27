/* qkd.c */

#include "qkd.h"
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <uuid/uuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Helper struct for storing response data */
struct MemoryStruct {
    char *memory;
    size_t size;
};

/* Callback function for handling data received from curl */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        // Out of memory
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0; // Null-terminate the string

    return realsize;
}

/* Base64 decoding function using OpenSSL */
static int Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    BIO *bio, *b64;
    int decodeLen = strlen(b64message);
    int padding = 0;

    if (b64message[decodeLen - 1] == '=' && b64message[decodeLen - 2] == '=') // Last two chars are '='
        padding = 2;
    else if (b64message[decodeLen - 1] == '=') // Last char is '='
        padding = 1;

    int expectedLen = (decodeLen * 3) / 4 - padding;

    *buffer = (unsigned char*)malloc(expectedLen);
    if (*buffer == NULL) {
        return -1;
    }

    bio = BIO_new_mem_buf(b64message, -1);
    if (bio == NULL) {
        free(*buffer);
        return -1;
    }
    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
        BIO_free(bio);
        free(*buffer);
        return -1;
    }
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines
    *length = BIO_read(bio, *buffer, decodeLen);
    BIO_free_all(bio);

    if (*length != expectedLen) {
        free(*buffer);
        return -1;
    }

    return 0;
}

/* Function to convert UUID string to bytes */
static int UUIDStringToBytes(const char* uuid_str, uint8_t* uuid_bytes) {
    uuid_t uuid;
    if (uuid_parse(uuid_str, uuid) != 0) {
        return -1; // Invalid UUID string
    }
    memcpy(uuid_bytes, uuid, KEY_ID_LENGTH);
    return 0;
}

/* Function to convert UUID bytes to string */
static void UUIDBytesToString(const uint8_t* uuid_bytes, char* uuid_str) {
    uuid_unparse(uuid_bytes, uuid_str);
}

int get_key_from_qkd(QKD_Credential *cred, QKD_Key *key) {
    if (key == NULL) {
        return -1;
    }

    if (cred == NULL || key == NULL) {
        return -1;
    }

    const char *qkd_user = cred->principal_name;
    if (strlen(qkd_user) > 128) {
        return -1;
    }

    memset(key, 0, sizeof(QKD_Key));

    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  // Will be grown as needed by realloc
    chunk.size = 0;            // No data at this point

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        // Set the URL
        char[256] qkd_url;
        snprintf(qkd_url, sizeof(qkd_url), "https://%s:%s/api/v1/keys/%s/enc_keys", "111.111.111.111", "12345", qkd_user)
        curl_easy_setopt(curl, CURLOPT_URL, qkd_url);

        // Set SSL options
        const char *env_ssl_cert_name = "QKD_SSL_CERT";
        char *env_ssl_cert_value = getenv(env_ssl_cert_name);

        if (env_ssl_cert_value != NULL) {
            curl_easy_setopt(curl, CURLOPT_SSLCERT, env_ssl_cert_value);
        } else {
            fprintf(stderr, "Environment variable %s is not set.\n", env_ssl_cert_name);
            curl_easy_cleanup(curl);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
        }

        const char *env_ssl_key_name = "QKD_SSL_CERT";
        char *env_ssl_key_value = getenv(env_ssl_key_name);

        if (env_ssl_key_value != NULL) {
            curl_easy_setopt(curl, CURLOPT_SSLKEY, env_ssl_key_value);
        } else {
            fprintf(stderr, "Environment variable %s is not set.\n", env_ssl_key_name);
            curl_easy_cleanup(curl);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
        }

        const char *env_ca_name = "QKD_SSL_CERT";
        char *env_ca_value = getenv(env_ca_name);

        if (env_ca_value != NULL) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, env_ca_value);
        } else {
            fprintf(stderr, "Environment variable %s is not set.\n", env_ca_name);
            curl_easy_cleanup(curl);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
        }

        // Set up callback function to capture the response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // Perform the request
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "get_key_from_qkd: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            // Handle the error
            curl_easy_cleanup(curl);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
        } else {
            // Parse the JSON response
            struct json_object *parsed_json;
            struct json_object *keys_array;
            struct json_object *key_obj;
            struct json_object *key_str_obj;
            struct json_object *key_id_obj;

            parsed_json = json_tokener_parse(chunk.memory);
            if (parsed_json == NULL) {
                fprintf(stderr, "get_key_from_qkd: Failed to parse JSON response\n");
                // Handle the error
                curl_easy_cleanup(curl);
                free(chunk.memory);
                curl_global_cleanup();
                return -1;
            } else {
                if (json_object_object_get_ex(parsed_json, "keys", &keys_array)) {
                    size_t n_keys = json_object_array_length(keys_array);
                    if (n_keys > 0) {
                        key_obj = json_object_array_get_idx(keys_array, 0);
                        if (json_object_object_get_ex(key_obj, "key", &key_str_obj) &&
                            json_object_object_get_ex(key_obj, "key_ID", &key_id_obj)) {

                            const char *key_b64_str = json_object_get_string(key_str_obj);
                            const char *key_id_str = json_object_get_string(key_id_obj);

                            // Base64 decode the key
                            unsigned char *key_data = NULL;
                            size_t key_data_len = 0;
                            if (Base64Decode(key_b64_str, &key_data, &key_data_len) == 0) {
                                if (key_data_len != KEY_LENGTH) {
                                    fprintf(stderr, "get_key_from_qkd: Invalid key length after Base64 decoding\n");
                                    free(key_data);
                                    json_object_put(parsed_json);
                                    curl_easy_cleanup(curl);
                                    free(chunk.memory);
                                    curl_global_cleanup();
                                    return -1;
                                } else {
                                    memcpy(key->key, key_data, KEY_LENGTH);
                                    free(key_data);
                                }
                            } else {
                                fprintf(stderr, "get_key_from_qkd: Failed to decode Base64 key\n");
                                json_object_put(parsed_json);
                                curl_easy_cleanup(curl);
                                free(chunk.memory);
                                curl_global_cleanup();
                                return -1;
                            }

                            // Convert UUID string to bytes
                            if (UUIDStringToBytes(key_id_str, key->key_id) != 0) {
                                fprintf(stderr, "get_key_from_qkd: Failed to convert key_ID to bytes\n");
                                json_object_put(parsed_json);
                                curl_easy_cleanup(curl);
                                free(chunk.memory);
                                curl_global_cleanup();
                                return -1;
                            }
                        } else {
                            fprintf(stderr, "get_key_from_qkd: JSON key object does not contain expected fields\n");
                            json_object_put(parsed_json);
                            curl_easy_cleanup(curl);
                            free(chunk.memory);
                            curl_global_cleanup();
                            return -1;
                        }
                    } else {
                        fprintf(stderr, "get_key_from_qkd: No keys available in response\n");
                        json_object_put(parsed_json);
                        curl_easy_cleanup(curl);
                        free(chunk.memory);
                        curl_global_cleanup();
                        return -1;
                    }
                } else {
                    fprintf(stderr, "get_key_from_qkd: JSON response does not contain 'keys' array\n");
                    json_object_put(parsed_json);
                    curl_easy_cleanup(curl);
                    free(chunk.memory);
                    curl_global_cleanup();
                    return -1;
                }

                // Free JSON object
                json_object_put(parsed_json);
            }

            // Clean up
            curl_easy_cleanup(curl);
        }

        // Clean up the memory chunk
        if (chunk.memory) {
            free(chunk.memory);
        }

        curl_global_cleanup();

        return 0; // Success
    } else {
        fprintf(stderr, "get_key_from_qkd: curl_easy_init() failed\n");
        curl_global_cleanup();
        return -1;
    }
}

int get_key_by_id(QKD_Credential *cred, const uint8_t key_id[KEY_ID_LENGTH], QKD_Key *key) {
    if (cred == NULL || key_id == NULL || key == NULL) {
        return -1;
    }

    const char *qkd_user = cred->principal_name;
    if (qkd_user == NULL || strlen(qkd_user) > 128) {
        return -1;
    }

    memset(key, 0, sizeof(QKD_Key));

    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  // Will be grown as needed by realloc
    chunk.size = 0;            // No data at this point

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        // Get QKD IP and port from environment variable
        const char *env_qkd_ipport_name = "QKD_IPPORT";
        char *env_qkd_ipport_value = getenv(env_qkd_ipport_name);
        if (env_qkd_ipport_value == NULL) {
            fprintf(stderr, "Environment variable %s is not set.\n", env_qkd_ipport_name);
            curl_easy_cleanup(curl);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
        }

        // Build the URL
        char qkd_url[256];
        snprintf(qkd_url, sizeof(qkd_url), "https://%s/api/v1/keys/%s/dec_keys", env_qkd_ipport_value, qkd_user);
        curl_easy_setopt(curl, CURLOPT_URL, qkd_url);

        // Set SSL options from environment variables
        const char *env_ssl_cert_name = "QKD_SSL_CERT";
        char *env_ssl_cert_value = getenv(env_ssl_cert_name);
        if (env_ssl_cert_value != NULL) {
            curl_easy_setopt(curl, CURLOPT_SSLCERT, env_ssl_cert_value);
        } else {
            fprintf(stderr, "Environment variable %s is not set.\n", env_ssl_cert_name);
            curl_easy_cleanup(curl);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
        }

        const char *env_ssl_key_name = "QKD_SSL_KEY";
        char *env_ssl_key_value = getenv(env_ssl_key_name);
        if (env_ssl_key_value != NULL) {
            curl_easy_setopt(curl, CURLOPT_SSLKEY, env_ssl_key_value);
        } else {
            fprintf(stderr, "Environment variable %s is not set.\n", env_ssl_key_name);
            curl_easy_cleanup(curl);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
        }

        const char *env_ca_name = "QKD_SSL_CA";
        char *env_ca_value = getenv(env_ca_name);
        if (env_ca_value != NULL) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, env_ca_value);
        } else {
            fprintf(stderr, "Environment variable %s is not set.\n", env_ca_name);
            curl_easy_cleanup(curl);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
        }

        // Ignore certificate validation errors if needed (equivalent to -k flag)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Prepare the POST data with key ID
        // Convert key_id (binary data) to UUID string
        char key_id_str[37]; // UUIDs are 36 characters plus null terminator
        uuid_unparse(key_id, key_id_str);

        // Prepare JSON data
        char post_data[256];
        snprintf(post_data, sizeof(post_data), "{ \"key_IDs\":[{ \"key_ID\": \"%s\" }] }", key_id_str);

        // Set POST method
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        // Set headers
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Set POST data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

        // Set up callback function to capture the response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // Perform the request
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "get_key_by_id: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            // Clean up
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            free(chunk.memory);
            curl_global_cleanup();
            return -1;
        } else {
            // Parse the JSON response
            struct json_object *parsed_json;
            struct json_object *keys_array;
            struct json_object *key_obj;
            struct json_object *key_str_obj;
            struct json_object *key_id_obj;

            parsed_json = json_tokener_parse(chunk.memory);
            if (parsed_json == NULL) {
                fprintf(stderr, "get_key_by_id: Failed to parse JSON response\n");
                // Clean up
                curl_easy_cleanup(curl);
                curl_slist_free_all(headers);
                free(chunk.memory);
                curl_global_cleanup();
                return -1;
            } else {
                if (json_object_object_get_ex(parsed_json, "keys", &keys_array)) {
                    size_t n_keys = json_object_array_length(keys_array);
                    if (n_keys > 0) {
                        key_obj = json_object_array_get_idx(keys_array, 0);
                        if (json_object_object_get_ex(key_obj, "key", &key_str_obj) &&
                            json_object_object_get_ex(key_obj, "key_ID", &key_id_obj)) {

                            const char *key_b64_str = json_object_get_string(key_str_obj);
                            const char *key_id_response_str = json_object_get_string(key_id_obj);

                            // Base64 decode the key
                            unsigned char *key_data = NULL;
                            size_t key_data_len = 0;
                            if (Base64Decode(key_b64_str, &key_data, &key_data_len) == 0) {
                                if (key_data_len != KEY_LENGTH) {
                                    fprintf(stderr, "get_key_by_id: Invalid key length after Base64 decoding\n");
                                    free(key_data);
                                    json_object_put(parsed_json);
                                    curl_easy_cleanup(curl);
                                    curl_slist_free_all(headers);
                                    free(chunk.memory);
                                    curl_global_cleanup();
                                    return -1;
                                } else {
                                    memcpy(key->key, key_data, KEY_LENGTH);
                                    free(key_data);
                                }
                            } else {
                                fprintf(stderr, "get_key_by_id: Failed to decode Base64 key\n");
                                json_object_put(parsed_json);
                                curl_easy_cleanup(curl);
                                curl_slist_free_all(headers);
                                free(chunk.memory);
                                curl_global_cleanup();
                                return -1;
                            }

                            // Convert key_ID in response back to bytes and compare with requested key_id
                            uint8_t response_key_id[KEY_ID_LENGTH];
                            if (UUIDStringToBytes(key_id_response_str, response_key_id) != 0) {
                                fprintf(stderr, "get_key_by_id: Failed to convert response key_ID to bytes\n");
                                json_object_put(parsed_json);
                                curl_easy_cleanup(curl);
                                curl_slist_free_all(headers);
                                free(chunk.memory);
                                curl_global_cleanup();
                                return -1;
                            }
                            if (memcmp(response_key_id, key_id, KEY_ID_LENGTH) != 0) {
                                fprintf(stderr, "get_key_by_id: Response key_ID does not match requested key_ID\n");
                                json_object_put(parsed_json);
                                curl_easy_cleanup(curl);
                                curl_slist_free_all(headers);
                                free(chunk.memory);
                                curl_global_cleanup();
                                return -1;
                            }
                            // Store the key_id
                            memcpy(key->key_id, key_id, KEY_ID_LENGTH);

                        } else {
                            fprintf(stderr, "get_key_by_id: JSON key object does not contain expected fields\n");
                            json_object_put(parsed_json);
                            curl_easy_cleanup(curl);
                            curl_slist_free_all(headers);
                            free(chunk.memory);
                            curl_global_cleanup();
                            return -1;
                        }
                    } else {
                        fprintf(stderr, "get_key_by_id: No keys available in response\n");
                        json_object_put(parsed_json);
                        curl_easy_cleanup(curl);
                        curl_slist_free_all(headers);
                        free(chunk.memory);
                        curl_global_cleanup();
                        return -1;
                    }
                } else {
                    fprintf(stderr, "get_key_by_id: JSON response does not contain 'keys' array\n");
                    json_object_put(parsed_json);
                    curl_easy_cleanup(curl);
                    curl_slist_free_all(headers);
                    free(chunk.memory);
                    curl_global_cleanup();
                    return -1;
                }
                // Free JSON object
                json_object_put(parsed_json);
            }
        }

        // Clean up
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        if (chunk.memory) free(chunk.memory);
        curl_global_cleanup();

        return 0; // Success
    } else {
        fprintf(stderr, "get_key_by_id: curl_easy_init() failed\n");
        curl_global_cleanup();
        return -1;
    }
}
