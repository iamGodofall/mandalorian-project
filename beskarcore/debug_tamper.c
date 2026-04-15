#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main() {
    // Simulate the encryption layout
    size_t plaintext_len = 11;  // "Secret data"
    size_t nonce_len = 12;
    size_t tag_len = 16;
    size_t ciphertext_len = nonce_len + plaintext_len + tag_len;  // 39
    
    printf("Ciphertext layout:\n");
    printf("  Nonce: bytes 0-%zu\n", nonce_len-1);
    printf("  Payload: bytes %zu-%zu\n", nonce_len, nonce_len+plaintext_len-1);
    printf("  Tag: bytes %zu-%zu\n", nonce_len+plaintext_len, ciphertext_len-1);
    printf("  Total: %zu bytes\n", ciphertext_len);
    
    // Tamper position 20
    size_t tamper_pos = 20;
    printf("\nTampering byte %zu\n", tamper_pos);
    printf("  This is in the %s region\n", 
           tamper_pos < nonce_len ? "NONCE" :
           tamper_pos < nonce_len+plaintext_len ? "PAYLOAD" : "TAG");
    
    // After tampering, decrypt will read:
    size_t encrypted_data_len = ciphertext_len - nonce_len;  // 27
    size_t payload_len = encrypted_data_len - tag_len;  // 11
    
    printf("\nDecrypt processing:\n");
    printf("  encrypted_data_len = %zu\n", encrypted_data_len);
    printf("  payload_len = %zu\n", payload_len);
    printf("  Will read checksum from encrypted_payload[%zu]\n", payload_len);
    printf("  This is ciphertext[%zu + %zu] = ciphertext[%zu]\n", nonce_len, payload_len, nonce_len+payload_len);
    
    return 0;
}
