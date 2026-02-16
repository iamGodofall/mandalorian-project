#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Simple Merkle tree implementation for Shield ledger
#define MAX_ENTRIES 1024
#define HASH_SIZE 32  // SHA3-256

typedef struct {
    uint64_t timestamp;
    char event_type[32];
    uint8_t data_hash[HASH_SIZE];
    uint8_t prev_hash[HASH_SIZE];
} ledger_entry_t;

static ledger_entry_t ledger[MAX_ENTRIES];
static int entry_count = 0;
static uint8_t root_hash[HASH_SIZE] = {0};

// Simple SHA3-256 implementation (Keccak-f[1600])
// Note: This is a basic implementation for demo purposes.
// In production, use a verified crypto library.

#define KECCAK_ROUNDS 24
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};

void keccakf(uint64_t st[25]) {
    int i, j, r;
    uint64_t t, bc[5];

    for (r = 0; r < KECCAK_ROUNDS; r++) {
        // Theta
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        // Iota
        st[0] ^= keccakf_rndc[r];
    }
}

int sha3_256(uint8_t *digest, const uint8_t *data, size_t len) {
    uint64_t st[25] = {0};
    size_t i, j;
    uint8_t *p = (uint8_t *)st;

    // Absorb
    for (i = 0; i < len; i++) {
        p[i % 200] ^= data[i];
        if ((i % 200) == 199) {
            keccakf(st);
        }
    }

    // Padding
    p[i % 200] ^= 0x06;
    p[199] ^= 0x80;
    keccakf(st);

    // Squeeze
    for (i = 0; i < 32; i++) {
        digest[i] = p[i];
    }

    return 0;
}

int add_ledger_entry(const char *event_type, const uint8_t *data_hash) {
    if (entry_count >= MAX_ENTRIES) {
        return -1; // Ledger full
    }

    ledger_entry_t *entry = &ledger[entry_count];
    entry->timestamp = (uint64_t)time(NULL);
    strncpy(entry->event_type, event_type, sizeof(entry->event_type));
    memcpy(entry->data_hash, data_hash, HASH_SIZE);
    memcpy(entry->prev_hash, root_hash, HASH_SIZE);

    // Compute new root hash
    uint8_t entry_data[sizeof(ledger_entry_t)];
    memcpy(entry_data, entry, sizeof(ledger_entry_t));
    sha3_256(root_hash, entry_data, sizeof(ledger_entry_t));

    entry_count++;
    return 0;
}

int get_root_hash(uint8_t *hash) {
    memcpy(hash, root_hash, HASH_SIZE);
    return 0;
}

int init_shield_ledger() {
    // Add initial entry
    uint8_t zero_hash[HASH_SIZE] = {0};
    add_ledger_entry("LEDGER_INIT", zero_hash);
    printf("Shield ledger initialized\n");
    return 0;
}
