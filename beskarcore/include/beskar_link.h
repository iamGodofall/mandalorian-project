#ifndef BESKAR_LINK_H
#define BESKAR_LINK_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// ============================================================================
// BESKAR LINK - Secure Messaging with Double Ratchet Protocol
// BlackBerry Messenger-inspired with modern Signal Protocol enhancements
// ============================================================================

#define BESKAR_LINK_VERSION "2.0.0"
#define BESKAR_LINK_PROTOCOL_VERSION 3

// Constants
#define BESKAR_LINK_MAX_CONTACTS 256
#define BESKAR_LINK_MAX_GROUPS 64
#define BESKAR_LINK_MAX_MESSAGE_SIZE 65536  // 64KB
#define BESKAR_LINK_MAX_PENDING_MESSAGES 1024
#define BESKAR_LINK_DEVICE_ID_SIZE 32
#define BESKAR_LINK_IDENTITY_KEY_SIZE 32
#define BESKAR_LINK_CHAIN_KEY_SIZE 32
#define BESKAR_LINK_MESSAGE_KEY_SIZE 32
#define BESKAR_LINK_MAX_DEVICES_PER_CONTACT 8
#define BESKAR_LINK_MAX_GROUP_MEMBERS 256
#define BESKAR_LINK_MAX_CALL_PARTICIPANTS 8

// ============================================================================
// Types and Enums
// ============================================================================

typedef enum {
    LINK_STATUS_OK = 0,
    LINK_STATUS_ERROR = -1,
    LINK_STATUS_INVALID_CONTACT = -2,
    LINK_STATUS_INVALID_MESSAGE = -3,
    LINK_STATUS_DECRYPTION_FAILED = -4,
    LINK_STATUS_RATchet_EXHAUSTED = -5,
    LINK_STATUS_DEVICE_UNTRUSTED = -6,
    LINK_STATUS_NETWORK_ERROR = -7,
    LINK_STATUS_RATE_LIMITED = -8
} link_status_t;

typedef enum {
    LINK_MESSAGE_TEXT = 0,
    LINK_MESSAGE_IMAGE = 1,
    LINK_MESSAGE_FILE = 2,
    LINK_MESSAGE_LOCATION = 3,
    LINK_MESSAGE_CONTACT = 4,
    LINK_MESSAGE_REACTION = 5,
    LINK_MESSAGE_CALL_SIGNAL = 6,
    LINK_MESSAGE_GROUP_CONTROL = 7
} link_message_type_t;

typedef enum {
    LINK_CALL_NONE = 0,
    LINK_CALL_OUTGOING = 1,
    LINK_CALL_INCOMING = 2,
    LINK_CALL_ACTIVE = 3,
    LINK_CALL_ENDED = 4
} link_call_state_t;

typedef enum {
    LINK_VERIFICATION_NONE = 0,
    LINK_VERIFICATION_SCANNED = 1,      // QR code scanned
    LINK_VERIFICATION_NUMBER = 2,         // Safety number verified
    LINK_VERIFICATION_TRUSTED = 3         // Manually trusted
} link_verification_level_t;

// ============================================================================
// Data Structures
// ============================================================================

// Double Ratchet state (per conversation)
typedef struct {
    uint8_t root_key[32];
    uint8_t chain_key_send[32];
    uint8_t chain_key_recv[32];
    uint32_t message_number_send;
    uint32_t message_number_recv;
    uint32_t previous_chain_length;
    bool ratchet_flag;  // True if we need to ratchet
} link_ratchet_state_t;

// Identity key (X25519)
typedef struct {
    uint8_t public_key[32];
    uint8_t private_key[32];  // Only stored in HSM
    time_t created_at;
    bool is_verified;
} link_identity_key_t;

// Device information
typedef struct {
    uint8_t device_id[32];
    link_identity_key_t identity_key;
    uint8_t pre_key[32];
    uint8_t pre_key_signature[64];
    time_t last_seen;
    bool is_active;
    link_verification_level_t verification;
} link_device_t;

// Contact information
typedef struct {
    uint8_t contact_id[32];
    char display_name[128];
    char phone_number[32];
    link_device_t devices[BESKAR_LINK_MAX_DEVICES_PER_CONTACT];
    uint32_t device_count;
    link_ratchet_state_t ratchet_state;
    bool is_blocked;
    bool is_verified;
    time_t added_at;
} link_contact_t;

// Message structure
typedef struct {
    uint64_t message_id;
    uint8_t sender_id[32];
    uint8_t recipient_id[32];
    link_message_type_t type;
    uint8_t ciphertext[BESKAR_LINK_MAX_MESSAGE_SIZE];
    size_t ciphertext_len;
    uint8_t message_key[32];  // Ephemeral key for this message
    uint32_t message_number;
    time_t timestamp;
    uint64_t reply_to_id;  // For threaded replies
    bool is_read;
    bool is_delivered;
    uint8_t attachments_hash[32];  // For file integrity
} link_message_t;

// Group information
typedef struct {
    uint8_t group_id[32];
    char group_name[128];
    uint8_t creator_id[32];
    uint8_t members[BESKAR_LINK_MAX_GROUP_MEMBERS][32];
    uint32_t member_count;
    link_ratchet_state_t group_ratchet;
    bool is_encrypted;  // E2EE group chat
    time_t created_at;
} link_group_t;

// Call session
typedef struct {
    uint64_t call_id;
    uint8_t caller_id[32];
    uint8_t participants[BESKAR_LINK_MAX_CALL_PARTICIPANTS][32];
    uint32_t participant_count;
    link_call_state_t state;
    time_t started_at;
    time_t ended_at;
    uint8_t encryption_key[32];  // SRTP key
    bool is_video;
} link_call_session_t;

// Configuration
typedef struct {
    bool enable_read_receipts;
    bool enable_typing_indicators;
    bool enable_delivery_receipts;
    bool enable_disappearing_messages;
    uint32_t disappearing_timer_seconds;
    bool require_verification;
    bool enable_perfect_forward_secrecy;
    uint32_t max_attachment_size;
    bool enable_voice_calls;
    bool enable_video_calls;
} link_config_t;

// Statistics
typedef struct {
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t messages_encrypted;
    uint64_t messages_decrypted;
    uint64_t calls_made;
    uint64_t calls_received;
    uint64_t bytes_encrypted;
    uint64_t bytes_decrypted;
    uint32_t active_sessions;
    uint32_t verified_contacts;
} link_stats_t;

// ============================================================================
// Core API Functions
// ============================================================================

// Initialization and lifecycle
int link_init(const link_config_t *config);
void link_shutdown(void);
bool link_is_initialized(void);
link_config_t link_get_config(void);
int link_update_config(const link_config_t *new_config);

// Identity management
int link_generate_identity(void);
int link_publish_pre_keys(uint32_t count);
int link_get_identity_public_key(uint8_t *public_key, size_t *len);
int link_verify_identity(uint8_t *contact_id, const uint8_t *public_key);

// Contact management
int link_add_contact(const char *phone_number, const char *display_name, 
                     link_contact_t *contact);
int link_remove_contact(const uint8_t *contact_id);
int link_get_contact(const uint8_t *contact_id, link_contact_t *contact);
int link_list_contacts(link_contact_t *contacts, uint32_t max_contacts, uint32_t *count);
int link_block_contact(const uint8_t *contact_id);
int link_unblock_contact(const uint8_t *contact_id);
int link_verify_contact(const uint8_t *contact_id, link_verification_level_t level);

// Session establishment (X3DH)
int link_initiate_session(const uint8_t *contact_id, const uint8_t *pre_key_bundle);
int link_respond_to_session(const uint8_t *contact_id, const uint8_t *session_request);
int link_close_session(const uint8_t *contact_id);

// Messaging
int link_send_message(const uint8_t *recipient_id, link_message_type_t type,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint64_t *message_id);
int link_receive_message(const uint8_t *sender_id, const link_message_t *message,
                         uint8_t *plaintext, size_t *plaintext_len);
int link_send_group_message(const uint8_t *group_id, link_message_type_t type,
                            const uint8_t *plaintext, size_t plaintext_len);
int link_delete_message(uint64_t message_id);
int link_get_message_status(uint64_t message_id, bool *is_delivered, bool *is_read);

// Group management
int link_create_group(const char *group_name, const uint8_t *initial_members[],
                      uint32_t member_count, uint8_t *group_id);
int link_join_group(const uint8_t *group_id, const uint8_t *invitation);
int link_leave_group(const uint8_t *group_id);
int link_add_group_member(const uint8_t *group_id, const uint8_t *member_id);
int link_remove_group_member(const uint8_t *group_id, const uint8_t *member_id);
int link_get_group_info(const uint8_t *group_id, link_group_t *group);

// Voice/Video calls
int link_initiate_call(const uint8_t *recipient_id, bool is_video, uint64_t *call_id);
int link_accept_call(uint64_t call_id);
int link_reject_call(uint64_t call_id);
int link_end_call(uint64_t call_id);
int link_get_call_info(uint64_t call_id, link_call_session_t *call);
int link_add_call_participant(uint64_t call_id, const uint8_t *participant_id);

// Double Ratchet operations
int link_ratchet_step_send(const uint8_t *contact_id);
int link_ratchet_step_receive(const uint8_t *contact_id, const uint8_t *new_public_key);
int link_derive_message_key(const uint8_t *chain_key, uint32_t message_number,
                            uint8_t *message_key);

// Security utilities
int link_encrypt_attachment(const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t *ciphertext, size_t *ciphertext_len,
                            uint8_t *key_out);
int link_decrypt_attachment(const uint8_t *ciphertext, size_t ciphertext_len,
                              const uint8_t *key, uint8_t *plaintext, size_t *plaintext_len);
int link_generate_safety_number(const uint8_t *contact_id, char *safety_number, size_t *len);
int link_verify_safety_number(const uint8_t *contact_id, const char *safety_number);

// Statistics and monitoring
link_stats_t link_get_stats(void);
int link_export_conversation(const uint8_t *contact_id, const char *filepath);
int link_import_conversation(const char *filepath);

// Utility functions
const char* link_message_type_to_string(link_message_type_t type);
const char* link_verification_level_to_string(link_verification_level_t level);
const char* link_call_state_to_string(link_call_state_t state);

#endif // BESKAR_LINK_H
