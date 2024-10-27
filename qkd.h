/* qkd.h */

#ifndef QKD_H
#define QKD_H

#include <stdint.h>
#include <stddef.h> // For size_t

/* Define constants */
#define KEY_LENGTH 32          // 256 bits
#define KEY_ID_LENGTH 16       // Assuming 128-bit key IDs

/* Define data structures */
typedef struct {
    uint8_t key_id[KEY_ID_LENGTH];
    uint8_t key[KEY_LENGTH];
} QKD_Key;

/* Credential structure */
typedef struct {
    char *principal_name; // Name of client
} QKD_Credential;

/* Function prototypes */

/**
 * @brief Retrieve a new key from the QKD device.
 *
 * @param[out] key  Pointer to a QKD_Key structure to store the retrieved key.
 * @return 0 on success, non-zero on failure.
 */
int get_key_from_qkd(QKD_Credential *cred, QKD_Key *key);

/**
 * @brief Retrieve a key from the QKD device by key ID.
 *
 * @param[in]  key_id  The key ID to retrieve.
 * @param[out] key     Pointer to a QKD_Key structure to store the retrieved key.
 * @return 0 on success, non-zero on failure.
 */
int get_key_by_id(QKD_Credential *cred, const uint8_t key_id[KEY_ID_LENGTH], QKD_Key *key);

#endif /* QKD_H */
