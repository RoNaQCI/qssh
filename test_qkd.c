/* test_qkd.c */

#include "qkd.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
    // Allocate and initialize the credential structure
    QKD_Credential *cred = (QKD_Credential *)malloc(sizeof(QKD_Credential));
    if (cred == NULL) {
        return -1;
    }

    // Initialize fields to NULL
    memset(cred, 0, sizeof(QKD_Credential));
    cred->principal_name = (char*)"BC_P";

    QKD_Key key;
    int result = get_key_from_qkd(cred, &key);

    if (result == 0) {
        // Print key_id and key in hex for testing purposes
        printf("Key ID: ");
        for (int i = 0; i < KEY_ID_LENGTH; i++) {
            printf("%02x", key.key_id[i]);
        }
        printf("\nKey Data: ");
        for (int i = 0; i < KEY_LENGTH; i++) {
            printf("%02x", key.key[i]);
        }
        printf("\n");
    } else {
        fprintf(stderr, "Failed to retrieve key from QKD device\n");
    }

    QKD_Key key_by_id;
    result = get_key_by_id(cred, key.key_id, &key_by_id);

    if (result == 0) {
        // Print key data
        printf("Retrieved Key Data by ID: ");
        for (int i = 0; i < KEY_LENGTH; i++) {
            printf("%02x", key_by_id.key[i]);
        }
        printf("\n");
    } else {
        fprintf(stderr, "Failed to retrieve key by ID from QKD device\n");
    }

    return 0;
}
