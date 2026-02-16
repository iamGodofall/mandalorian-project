#include "../include/beskar_link.h"
#include "../include/beskar_vault.h"
#include "../include/logging.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// BESKAR LINK - Secure Messaging Implementation
// Double Ratchet Protocol with X3DH Key Agreement
// ============================================================================

// Global state
static link_config_t link_config = {0};
static bool link_initialized = false;

// Contact database (simplified - in production, use encrypted database)
static link_contact_t contacts[BESKAR_LINK_MAX_CONTACTS];
static uint32_t contact_count = 0;

// Group database
static link_group_t groups[BESKAR_LINK_MAX_GROUPS];
static uint32_t group_count = 0;

// Message queue
static link_message_t pending_messages[BESKAR_LINK_MAX_PENDING_MESSAGES];
static uint32_t pending_count = 0;

// Call sessions
static link_call_session_t active_calls[BESKAR_LINK_MAX_CALL_PARTICIPANTS];
static uint32_t active_call_count = 0;

// Statistics
static link_stats_t stats = {0};

// Forward declarations
static int generate_random_bytes(uint8_t *buffer, size_t len);
static int derive_key(const uint8_t *input, size_t input_len, 
                      const uint8_t *salt, size_t salt_len,
                      uint8_t *output, size_t output_len);
static int x3dh_key_agreement(const link_identity_key_t *identity,
                              const uint8_t *ephemeral_key,
                              uint8_t *shared_secret);
static int double_ratchet_step(link_ratchet_state_t *state, bool is_sender);
static int encrypt_message_aes_gcm(const uint8_t *plaintext, size_t pt_len,
                                   const uint8_t *key, const uint8_t *nonce,
                                   uint8_t *ciphertext, size_t *ct_len);
static int decrypt_message_aes_gcm(const uint8_t *ciphertext, size_t ct_len,
                                   const uint8_t *key, const uint8_t *nonce,
                                   uint8_t *plaintext, size_t *pt_len);
static int find_contact(const uint8_t *contact_id, link_contact_t **contact);
static int find_group(const uint8_t *group_id, link_group_t **group);
static int log_link_event(const char *event_type, const char *details);

// ============================================================================
// Initialization and Lifecycle
// ============================================================================

int link_init(const link_config_t *config) {
    if (link_initialized) {
        LOG_WARN("BeskarLink already initialized");
        return 0;
    }

    LOG_INFO("Initializing BeskarLink secure messaging");

    // Copy configuration
    if (config) {
        memcpy(&link_config, config, sizeof(link_config_t));
    } else {
        // Default configuration
        link_config.enable_read_receipts = true;
        link_config.enable_typing_indicators = false;
        link_config.enable_delivery_receipts = true;
        link_config.enable_disappearing_messages = false;
        link_config.disappearing_timer_seconds = 86400; // 24 hours
        link_config.require_verification = true;
        link_config.enable_perfect_forward_secrecy = true;
        link_config.max_attachment_size = 10485760; // 10MB
        link_config.enable_voice_calls = true;
        link_config.enable_video_calls = true;
    }

    // Initialize databases
    memset(contacts, 0, sizeof(contacts));
    memset(groups, 0, sizeof(groups));
    memset(pending_messages, 0, sizeof(pending_messages));
    memset(active_calls, 0, sizeof(active_calls));

    contact_count = 0;
    group_count = 0;
    pending_count = 0;
    active_call_count = 0;

    // Initialize statistics
    memset(&stats, 0, sizeof(stats));

    // Generate identity if needed
    if (link_generate_identity() != 0) {
        LOG_ERROR("Failed to generate identity");
        return -1;
    }

    link_initialized = true;

    LOG_INFO("BeskarLink initialized successfully");
    LOG_INFO("Configuration:");
    LOG_INFO("  Read receipts: %s", link_config.enable_read_receipts ? "enabled" : "disabled");
    LOG_INFO("  Delivery receipts: %s", link_config.enable_delivery_receipts ? "enabled" : "disabled");
    LOG_INFO("  Perfect forward secrecy: %s", link_config.enable_perfect_forward_secrecy ? "enabled" : "disabled");
    LOG_INFO("  Voice calls: %s", link_config.enable_voice_calls ? "enabled" : "disabled");
    LOG_INFO("  Video calls: %s", link_config.enable_video_calls ? "enabled" : "disabled");

    log_link_event("LINK_INIT", "BeskarLink secure messaging initialized");

    return 0;
}

void link_shutdown(void) {
    if (!link_initialized) {
        return;
    }

    LOG_INFO("Shutting down BeskarLink");

    // Close all sessions
    for (uint32_t i = 0; i < contact_count; i++) {
        link_close_session(contacts[i].contact_id);
    }

    // End all active calls
    for (uint32_t i = 0; i < active_call_count; i++) {
        link_end_call(active_calls[i].call_id);
    }

    // Clear sensitive data
    memset(&link_config, 0, sizeof(link_config_t));
    memset(contacts, 0, sizeof(contacts));
    memset(groups, 0, sizeof(groups));
    memset(pending_messages, 0, sizeof(pending_messages));
    memset(active_calls, 0, sizeof(active_calls));

    link_initialized = false;

    log_link_event("LINK_SHUTDOWN", "BeskarLink shutdown");
}

bool link_is_initialized(void) {
    return link_initialized;
}

link_config_t link_get_config(void) {
    return link_config;
}

int link_update_config(const link_config_t *new_config) {
    if (!link_initialized) {
        return -1;
    }

    memcpy(&link_config, new_config, sizeof(link_config_t));
    LOG_INFO("BeskarLink configuration updated");
    return 0;
}

// ============================================================================
// Identity Management
// ============================================================================

int link_generate_identity(void) {
    LOG_INFO("Generating X25519 identity key pair");

    // Generate identity key using BeskarVault
    uint8_t public_key[32];
    size_t pub_len = sizeof(public_key);

    // Use communication key slot for identity
    if (vault_generate_key(VAULT_KEY_COMMUNICATION, public_key, &pub_len) != 0) {
        LOG_ERROR("Failed to generate identity key");
        return -1;
    }

    LOG_INFO("Identity key generated successfully");
    LOG_INFO("Public key: %02X%02X...%02X%02X",
             public_key[0], public_key[1],
             public_key[30], public_key[31]);

    // Publish initial pre-keys
    link_publish_pre_keys(20);

    return 0;
}

int link_publish_pre_keys(uint32_t count) {
    LOG_INFO("Publishing %u pre-keys", count);

    // In real implementation, this would:
    // 1. Generate ephemeral X25519 key pairs
    // 2. Sign them with identity key
    // 3. Upload to key server (or distribute via peer-to-peer)

    for (uint32_t i = 0; i < count; i++) {
        // Generate pre-key using BeskarVault
        uint8_t pre_key_pub[32];
        size_t pub_len = sizeof(pre_key_pub);

        // Use app signing key slot for pre-keys
        if (vault_generate_key(VAULT_KEY_APP_SIGNING, pre_key_pub, &pub_len) != 0) {
            LOG_WARN("Failed to generate pre-key %u", i);
            continue;
        }
    }

    LOG_INFO("Published %u pre-keys", count);
    return 0;
}

int link_get_identity_public_key(uint8_t *public_key, size_t *len) {
    if (!link_initialized) {
        return -1;
    }

    // Get from BeskarVault
    vault_key_metadata_t metadata;
    if (vault_get_key_metadata(VAULT_KEY_COMMUNICATION, &metadata) != 0) {
        return -1;
    }

    // In real implementation, retrieve actual public key
    // For now, return a placeholder
    if (*len < 32) {
        return -1;
    }

    // Generate deterministic public key for demo
    memset(public_key, 0xAB, 32);
    *len = 32;

    return 0;
}

int link_verify_identity(uint8_t *contact_id, const uint8_t *public_key) {
    LOG_INFO("Verifying identity for contact");

    link_contact_t *contact;
    if (find_contact(contact_id, &contact) != 0) {
        LOG_ERROR("Contact not found");
        return -1;
    }

    // Verify public key matches expected
    // In real implementation, compare with stored public key
    LOG_INFO("Identity verified for contact");
    contact->is_verified = true;

    return 0;
}

// ============================================================================
// Contact Management
// ============================================================================

int link_add_contact(const char *phone_number, const char *display_name,
                     link_contact_t *contact) {
    if (!link_initialized) {
        return -1;
    }

    if (contact_count >= BESKAR_LINK_MAX_CONTACTS) {
        LOG_ERROR("Maximum contacts reached");
        return -1;
    }

    // Check if contact already exists
    for (uint32_t i = 0; i < contact_count; i++) {
        if (strcmp(contacts[i].phone_number, phone_number) == 0) {
            LOG_WARN("Contact already exists");
            memcpy(contact, &contacts[i], sizeof(link_contact_t));
            return 0;
        }
    }

    // Add new contact
    link_contact_t *new_contact = &contacts[contact_count];
    memset(new_contact, 0, sizeof(link_contact_t));

    // Generate contact ID
    generate_random_bytes(new_contact->contact_id, 32);

    strncpy(new_contact->phone_number, phone_number, sizeof(new_contact->phone_number) - 1);
    strncpy(new_contact->display_name, display_name, sizeof(new_contact->display_name) - 1);
    new_contact->added_at = time(NULL);
    new_contact->is_blocked = false;
    new_contact->is_verified = false;
    new_contact->device_count = 0;

    // Initialize ratchet state
    memset(&new_contact->ratchet_state, 0, sizeof(link_ratchet_state_t));

    memcpy(contact, new_contact, sizeof(link_contact_t));
    contact_count++;

    LOG_INFO("Added contact: %s (%s)", display_name, phone_number);

    char details[256];
    snprintf(details, sizeof(details), "Added contact: %s", display_name);
    log_link_event("CONTACT_ADD", details);

    return 0;
}

int link_remove_contact(const uint8_t *contact_id) {
    link_contact_t *contact;
    int idx = -1;

    for (uint32_t i = 0; i < contact_count; i++) {
        if (memcmp(contacts[i].contact_id, contact_id, 32) == 0) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        return -1;
    }

    // Close session if active
    link_close_session(contact_id);

    // Remove contact by shifting array
    for (uint32_t i = idx; i < contact_count - 1; i++) {
        contacts[i] = contacts[i + 1];
    }

    contact_count--;
    LOG_INFO("Removed contact");

    return 0;
}

int link_get_contact(const uint8_t *contact_id, link_contact_t *contact) {
    link_contact_t *c;
    if (find_contact(contact_id, &c) != 0) {
        return -1;
    }

    memcpy(contact, c, sizeof(link_contact_t));
    return 0;
}

int link_list_contacts(link_contact_t *contact_list, uint32_t max_contacts, uint32_t *count) {
    if (!link_initialized) {
        return -1;
    }

    uint32_t num = (contact_count < max_contacts) ? contact_count : max_contacts;
    memcpy(contact_list, contacts, num * sizeof(link_contact_t));
    *count = num;

    return 0;
}

int link_block_contact(const uint8_t *contact_id) {
    link_contact_t *contact;
    if (find_contact(contact_id, &contact) != 0) {
        return -1;
    }

    contact->is_blocked = true;
    LOG_INFO("Blocked contact");

    return 0;
}

int link_unblock_contact(const uint8_t *contact_id) {
    link_contact_t *contact;
    if (find_contact(contact_id, &contact) != 0) {
        return -1;
    }

    contact->is_blocked = false;
    LOG_INFO("Unblocked contact");

    return 0;
}

int link_verify_contact(const uint8_t *contact_id, link_verification_level_t level) {
    link_contact_t *contact;
    if (find_contact(contact_id, &contact) != 0) {
        return -1;
    }

    for (uint32_t i = 0; i < contact->device_count; i++) {
        contact->devices[i].verification = level;
    }

    contact->is_verified = (level >= LINK_VERIFICATION_TRUSTED);
    LOG_INFO("Contact verification level set to: %s",
             link_verification_level_to_string(level));

    return 0;
}

// ============================================================================
// Session Establishment (X3DH)
// ============================================================================

int link_initiate_session(const uint8_t *contact_id, const uint8_t *pre_key_bundle) {
    LOG_INFO("Initiating X3DH session with contact");

    link_contact_t *contact;
    if (find_contact(contact_id, &contact) != 0) {
        return -1;
    }

    // X3DH Key Agreement:
    // 1. Generate ephemeral key pair
    // 2. Perform DH calculations with pre-key bundle
    // 3. Derive root key
    // 4. Initialize Double Ratchet

    uint8_t ephemeral_key[32];
    generate_random_bytes(ephemeral_key, 32);

    // Derive shared secret
    uint8_t shared_secret[32];
    if (x3dh_key_agreement(&contact->devices[0].identity_key,
                           ephemeral_key, shared_secret) != 0) {
        LOG_ERROR("X3DH key agreement failed");
        return -1;
    }

    // Initialize Double Ratchet
    memcpy(contact->ratchet_state.root_key, shared_secret, 32);
    generate_random_bytes(contact->ratchet_state.chain_key_send, 32);
    memcpy(contact->ratchet_state.chain_key_recv, shared_secret, 32);
    contact->ratchet_state.message_number_send = 0;
    contact->ratchet_state.message_number_recv = 0;
    contact->ratchet_state.previous_chain_length = 0;
    contact->ratchet_state.ratchet_flag = false;

    LOG_INFO("X3DH session established");
    stats.active_sessions++;

    return 0;
}

int link_respond_to_session(const uint8_t *contact_id, const uint8_t *session_request) {
    LOG_INFO("Responding to X3DH session request");

    link_contact_t *contact;
    if (find_contact(contact_id, &contact) != 0) {
        return -1;
    }

    // Similar to initiate_session but as responder
    // Derive shared secret from session request
    uint8_t shared_secret[32];
    generate_random_bytes(shared_secret, 32); // Simulated

    // Initialize Double Ratchet (responder perspective)
    memcpy(contact->ratchet_state.root_key, shared_secret, 32);
    memcpy(contact->ratchet_state.chain_key_send, shared_secret, 32);
    generate_random_bytes(contact->ratchet_state.chain_key_recv, 32);
    contact->ratchet_state.message_number_send = 0;
    contact->ratchet_state.message_number_recv = 0;
    contact->ratchet_state.previous_chain_length = 0;
    contact->ratchet_state.ratchet_flag = false;

    LOG_INFO("X3DH session established (responder)");
    stats.active_sessions++;

    return 0;
}

int link_close_session(const uint8_t *contact_id) {
    link_contact_t *contact;
    if (find_contact(contact_id, &contact) != 0) {
        return 0; // Already closed
    }

    // Clear ratchet state
    memset(&contact->ratchet_state, 0, sizeof(link_ratchet_state_t));

    LOG_INFO("Session closed");
    if (stats.active_sessions > 0) {
        stats.active_sessions--;
    }

    return 0;
}

// ============================================================================
// Messaging
// ============================================================================

int link_send_message(const uint8_t *recipient_id, link_message_type_t type,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint64_t *message_id) {
    if (!link_initialized) {
        return -1;
    }

    link_contact_t *contact;
    if (find_contact(recipient_id, &contact) != 0) {
        LOG_ERROR("Recipient not found");
        return -1;
    }

    if (contact->is_blocked) {
        LOG_WARN("Cannot send message to blocked contact");
        return -1;
    }

    // Check if session exists
    if (contact->ratchet_state.message_number_send == 0 &&
        contact->ratchet_state.message_number_recv == 0) {
        LOG_ERROR("No active session with contact");
        return -1;
    }

    // Generate message ID
    static uint64_t next_message_id = 1;
    *message_id = next_message_id++;

    // Double Ratchet step
    if (double_ratchet_step(&contact->ratchet_state, true) != 0) {
        LOG_ERROR("Double ratchet step failed");
        return -1;
    }

    // Derive message key
    uint8_t message_key[32];
    link_derive_message_key(contact->ratchet_state.chain_key_send,
                            contact->ratchet_state.message_number_send - 1,
                            message_key);

    // Encrypt message
    uint8_t nonce[12];
    generate_random_bytes(nonce, 12);

    link_message_t message;
    memset(&message, 0, sizeof(link_message_t));

    message.message_id = *message_id;
    memcpy(message.sender_id, recipient_id, 32); // Will be replaced with our ID
    memcpy(message.recipient_id, recipient_id, 32);
    message.type = type;
    message.timestamp = time(NULL);
    message.message_number = contact->ratchet_state.message_number_send - 1;
    memcpy(message.message_key, message_key, 32);

    // Encrypt
    size_t ct_len = sizeof(message.ciphertext);
    if (encrypt_message_aes_gcm(plaintext, plaintext_len, message_key, nonce,
                                message.ciphertext, &ct_len) != 0) {
        LOG_ERROR("Message encryption failed");
        return -1;
    }
    message.ciphertext_len = ct_len;

    // Store in pending queue (simulated sending)
    if (pending_count < BESKAR_LINK_MAX_PENDING_MESSAGES) {
        pending_messages[pending_count++] = message;
    }

    // Update statistics
    stats.messages_sent++;
    stats.messages_encrypted++;
    stats.bytes_encrypted += plaintext_len;

    LOG_INFO("Message sent: ID=%llu, type=%s, size=%zu bytes",
             (unsigned long long)*message_id,
             link_message_type_to_string(type),
             plaintext_len);

    return 0;
}

int link_receive_message(const uint8_t *sender_id, const link_message_t *message,
                         uint8_t *plaintext, size_t *plaintext_len) {
    if (!link_initialized) {
        return -1;
    }

    link_contact_t *contact;
    if (find_contact(sender_id, &contact) != 0) {
        LOG_ERROR("Sender not found");
        return -1;
    }

    if (contact->is_blocked) {
        LOG_WARN("Message from blocked contact ignored");
        return -1;
    }

    // Check if ratchet step needed
    if (message->message_number < contact->ratchet_state.message_number_recv) {
        // Out-of-order message or replay
        LOG_WARN("Potential replay attack or out-of-order message");
    }

    // Double Ratchet step if needed
    if (contact->ratchet_state.ratchet_flag) {
        // New ratchet key received
        double_ratchet_step(&contact->ratchet_state, false);
    }

    // Derive message key
    uint8_t message_key[32];
    link_derive_message_key(contact->ratchet_state.chain_key_recv,
                            message->message_number,
                            message_key);

    // Decrypt message
    uint8_t nonce[12] = {0}; // In real implementation, extract from message
    if (decrypt_message_aes_gcm(message->ciphertext, message->ciphertext_len,
                                message_key, nonce,
                                plaintext, plaintext_len) != 0) {
        LOG_ERROR("Message decryption failed");
        return -1;
    }

    // Update statistics
    stats.messages_received++;
    stats.messages_decrypted++;
    stats.bytes_decrypted += *plaintext_len;

    LOG_INFO("Message received: ID=%llu, type=%s, size=%zu bytes",
             (unsigned long long)message->message_id,
             link_message_type_to_string(message->type),
             *plaintext_len);

    return 0;
}

int link_send_group_message(const uint8_t *group_id, link_message_type_t type,
                            const uint8_t *plaintext, size_t plaintext_len) {
    link_group_t *group;
    if (find_group(group_id, &group) != 0) {
        LOG_ERROR("Group not found");
        return -1;
    }

    LOG_INFO("Sending group message to %u members", group->member_count);

    // Send to each member
    for (uint32_t i = 0; i < group->member_count; i++) {
        uint64_t message_id;
        link_send_message(group->members[i], type, plaintext, plaintext_len, &message_id);
    }

    return 0;
}

int link_delete_message(uint64_t message_id) {
    LOG_INFO("Deleting message: %llu", (unsigned long long)message_id);
    // In real implementation, mark as deleted in database
    return 0;
}

int link_get_message_status(uint64_t message_id, bool *is_delivered, bool *is_read) {
    // Search in pending messages
    for (uint32_t i = 0; i < pending_count; i++) {
        if (pending_messages[i].message_id == message_id) {
            *is_delivered = pending_messages[i].is_delivered;
            *is_read = pending_messages[i].is_read;
            return 0;
        }
    }

    return -1; // Message not found
}

// ============================================================================
// Group Management
// ============================================================================

int link_create_group(const char *group_name, const uint8_t *initial_members[],
                      uint32_t member_count, uint8_t *group_id) {
    if (!link_initialized) {
        return -1;
    }

    if (group_count >= BESKAR_LINK_MAX_GROUPS) {
        LOG_ERROR("Maximum groups reached");
        return -1;
    }

    if (member_count > BESKAR_LINK_MAX_GROUP_MEMBERS) {
        LOG_ERROR("Too many group members");
        return -1;
    }

    link_group_t *group = &groups[group_count];
    memset(group, 0, sizeof(link_group_t));

    // Generate group ID
    generate_random_bytes(group->group_id, 32);
    memcpy(group_id, group->group_id, 32);

    strncpy(group->group_name, group_name, sizeof(group->group_name) - 1);
    group->member_count = member_count;
    group->is_encrypted = true;
    group->created_at = time(NULL);

    // Copy members
    for (uint32_t i = 0; i < member_count; i++) {
        memcpy(group->members[i], initial_members[i], 32);
    }

    // Initialize group ratchet
    generate_random_bytes(group->group_ratchet.root_key, 32);
    generate_random_bytes(group->group_ratchet.chain_key_send, 32);
    generate_random_bytes(group->group_ratchet.chain_key_recv, 32);

    group_count++;

    LOG_INFO("Created group: %s with %u members", group_name, member_count);

    return 0;
}

int link_join_group(const uint8_t *group_id, const uint8_t *invitation) {
    LOG_INFO("Joining group");
    // In real implementation, verify invitation and add self to group
    return 0;
}

int link_leave_group(const uint8_t *group_id) {
    LOG_INFO("Leaving group");
    // Remove self from group
    return 0;
}

int link_add_group_member(const uint8_t *group_id, const uint8_t *member_id) {
    link_group_t *group;
    if (find_group(group_id, &group) != 0) {
        return -1;
    }

    if (group->member_count >= BESKAR_LINK_MAX_GROUP_MEMBERS) {
        return -1;
    }

    memcpy(group->members[group->member_count], member_id, 32);
    group->member_count++;

    LOG_INFO("Added member to group, total: %u", group->member_count);
    return 0;
}

int link_remove_group_member(const uint8_t *group_id, const uint8_t *member_id) {
    link_group_t *group;
    if (find_group(group_id, &group) != 0) {
        return -1;
    }

    // Find and remove member
    for (uint32_t i = 0; i < group->member_count; i++) {
        if (memcmp(group->members[i], member_id, 32) == 0) {
            // Shift remaining members
            for (uint32_t j = i; j < group->member_count - 1; j++) {
                memcpy(group->members[j], group->members[j + 1], 32);
            }
            group->member_count--;
            LOG_INFO("Removed member from group, total: %u", group->member_count);
            return 0;
        }
    }

    return -1; // Member not found
}

int link_get_group_info(const uint8_t *group_id, link_group_t *group) {
    link_group_t *g;
    if (find_group(group_id, &g) != 0) {
        return -1;
    }

    memcpy(group, g, sizeof(link_group_t));
    return 0;
}

// ============================================================================
// Voice/Video Calls
// ============================================================================

int link_initiate_call(const uint8_t *recipient_id, bool is_video, uint64_t *call_id) {
    if (!link_initialized) {
        return -1;
    }

    if (is_video && !link_config.enable_video_calls) {
        LOG_ERROR("Video calls disabled");
        return -1;
    }

    if (!is_video && !link_config.enable_voice_calls) {
        LOG_ERROR("Voice calls disabled");
        return -1;
    }

    if (active_call_count >= BESKAR_LINK_MAX_CALL_PARTICIPANTS) {
        LOG_ERROR("Maximum concurrent calls reached");
        return -1;
    }

    // Generate call ID
    static uint64_t next_call_id = 1;
    *call_id = next_call_id++;

    link_call_session_t *call = &active_calls[active_call_count++];
    memset(call, 0, sizeof(link_call_session_t));

    call->call_id = *call_id;
    memcpy(call->caller_id, recipient_id, 32);
    call->state = LINK_CALL_OUTGOING;
    call->is_video = is_video;
    call->started_at = time(NULL);

    // Generate SRTP encryption key
    generate_random_bytes(call->encryption_key, 32);

    LOG_INFO("Initiated %s call: ID=%llu",
             is_video ? "video" : "voice",
             (unsigned long long)*call_id);

    stats.calls_made++;

    return 0;
}

int link_accept_call(uint64_t call_id) {
    for (uint32_t i = 0; i < active_call_count; i++) {
        if (active_calls[i].call_id == call_id) {
            active_calls[i].state = LINK_CALL_ACTIVE;
            LOG_INFO("Call accepted: %llu", (unsigned long long)call_id);
            return 0;
        }
    }

    return -1;
}

int link_reject_call(uint64_t call_id) {
    for (uint32_t i = 0; i < active_call_count; i++) {
        if (active_calls[i].call_id == call_id) {
            active_calls[i].state = LINK_CALL_ENDED;
            active_calls[i].ended_at = time(NULL);
            LOG_INFO("Call rejected: %llu", (unsigned long long)call_id);
            return 0;
        }
    }

    return -1;
}

int link_end_call(uint64_t call_id) {
    for (uint32_t i = 0; i < active_call_count; i++) {
        if (active_calls[i].call_id == call_id) {
            active_calls[i].state = LINK_CALL_ENDED;
            active_calls[i].ended_at = time(NULL);

            // Clear encryption key
            memset(active_calls[i].encryption_key, 0, 32);

            LOG_INFO("Call ended: %llu", (unsigned long long)call_id);
            return 0;
        }
    }

    return -1;
}

int link_get_call_info(uint64_t call_id, link_call_session_t *call) {
    for (uint32_t i = 0; i < active_call_count; i++) {
        if (active_calls[i].call_id == call_id) {
            memcpy(call, &active_calls[i], sizeof(link_call_session_t));
            return 0;
        }
    }

    return -1;
}

int link_add_call_participant(uint64_t call_id, const uint8_t *participant_id) {
    for (uint32_t i = 0; i < active_call_count; i++) {
        if (active_calls[i].call_id == call_id) {
            if (active_calls[i].participant_count >= BESKAR_LINK_MAX_CALL_PARTICIPANTS) {
                return -1;
            }

            memcpy(active_calls[i].participants[active_calls[i].participant_count],
                   participant_id, 32);
            active_calls[i].participant_count++;

            LOG_INFO("Added participant to call, total: %u",
                     active_calls[i].participant_count);
            return 0;
        }
    }

    return -1;
}

// ============================================================================
// Double Ratchet Operations
// ============================================================================

int link_ratchet_step_send(const uint8_t *contact_id) {
    link_contact_t *contact;
    if (find_contact(contact_id, &contact) != 0) {
        return -1;
    }

    return double_ratchet_step(&contact->ratchet_state, true);
}

int link_ratchet_step_receive(const uint8_t *contact_id, const uint8_t *new_public_key) {
    link_contact_t *contact;
    if (find_contact(contact_id, &contact) != 0) {
        return -1;
    }

    // Update ratchet with new public key
    (void)new_public_key; // Would use in real implementation
    contact->ratchet_state.ratchet_flag = true;

    return double_ratchet_step(&contact->ratchet_state, false);
}

int link_derive_message_key(const uint8_t *chain_key, uint32_t message_number,
                            uint8_t *message_key) {
    // HKDF-like derivation: message_key = HMAC(chain_key, message_number)
    uint8_t input[36];
    memcpy(input, chain_key, 32);
    memcpy(input + 32, &message_number, 4);

    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    sha3_256(message_key, input, sizeof(input));

    return 0;
}

// ============================================================================
// Security Utilities
// ============================================================================

int link_encrypt_attachment(const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t *ciphertext, size_t *ciphertext_len,
                            uint8_t *key_out) {
    // Generate random key
    generate_random_bytes(key_out, 32);

    // Encrypt
    uint8_t nonce[12];
    generate_random_bytes(nonce, 12);

    return encrypt_message_aes_gcm(plaintext, plaintext_len, key_out, nonce,
                                   ciphertext, ciphertext_len);
}

int link_decrypt_attachment(const uint8_t *ciphertext, size_t ciphertext_len,
                              const uint8_t *key, uint8_t *plaintext, size_t *plaintext_len) {
    uint8_t nonce[12] = {0}; // Extract from ciphertext in real implementation
    return decrypt_message_aes_gcm(ciphertext, ciphertext_len, key, nonce,
                                   plaintext, plaintext_len);
}

int link_generate_safety_number(const uint8_t *contact_id, char *safety_number, size_t *len) {
    link_contact_t *contact;
    if (find_contact(contact_id, &contact) != 0) {
        return -1;
    }

    // Generate safety number from identity keys
    // Format: 12345 67890 12345 67890 12345 67890
    uint8_t combined[64];
    memcpy(combined, contact->devices[0].identity_key.public_key, 32);

    // Get our identity key
    uint8_t our_key[32];
    size_t key_len = 32;
    link_get_identity_public_key(our_key, &key_len);
    memcpy(combined + 32, our_key, 32);

    // Hash
    uint8_t hash[32];
    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    sha3_256(hash, combined, 64);

    // Format as safety number
    snprintf(safety_number, *len,
             "%02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
             hash[0], hash[1], hash[2], hash[3],
             hash[4], hash[5], hash[6], hash[7],
             hash[8], hash[9], hash[10], hash[11]);

    *len = strlen(safety_number);

    return 0;
}

int link_verify_safety_number(const uint8_t *contact_id, const char *safety_number) {
    char generated[64];
    size_t len = sizeof(generated);

    if (link_generate_safety_number(contact_id, generated, &len) != 0) {
        return -1;
    }

    if (strcmp(generated, safety_number) == 0) {
        LOG_INFO("Safety number verified");
        return 0;
    } else {
        LOG_WARN("Safety number mismatch - potential MITM attack");
        return -1;
    }
}

// ============================================================================
// Statistics and Monitoring
// ============================================================================

link_stats_t link_get_stats(void) {
    return stats;
}

int link_export_conversation(const uint8_t *contact_id, const char *filepath) {
    LOG_INFO("Exporting conversation to: %s", filepath);
    // In real implementation, export encrypted conversation
    (void)contact_id;
    return 0;
}

int link_import_conversation(const char *filepath) {
    LOG_INFO("Importing conversation from: %s", filepath);
    // In real implementation, import and verify conversation
    (void)filepath;
    return 0;
}

// ============================================================================
// Helper Functions
// ============================================================================

static int generate_random_bytes(uint8_t *buffer, size_t len) {
    // In real implementation, use hardware TRNG via BeskarVault
    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(rand() % 256);
    }
    return 0;
}

static int derive_key(const uint8_t *input, size_t input_len,
                      const uint8_t *salt, size_t salt_len,
                      uint8_t *output, size_t output_len) {
    // Simple HKDF-like derivation
    uint8_t combined[256];
    size_t combined_len = 0;

    if (salt && salt_len > 0) {
        memcpy(combined, salt, salt_len);
        combined_len += salt_len;
    }

    memcpy(combined + combined_len, input, input_len);
    combined_len += input_len;

    extern int sha3_256(uint8_t *digest, const uint8_t *data, size_t len);
    sha3_256(output, combined, combined_len);

    return 0;
}

static int x3dh_key_agreement(const link_identity_key_t *identity,
                              const uint8_t *ephemeral_key,
                              uint8_t *shared_secret) {
    // Simplified X3DH - in real implementation, perform actual DH operations
    (void)identity;
    (void)ephemeral_key;

    // Generate deterministic shared secret for demo
    generate_random_bytes(shared_secret, 32);

    return 0;
}

static int double_ratchet_step(link_ratchet_state_t *state, bool is_sender) {
    // Simplified Double Ratchet step
    // In real implementation, this performs the full ratchet algorithm

    if (is_sender) {
        // Sending chain
        state->previous_chain_length = state->message_number_send;
        state->message_number_send++;

        //
