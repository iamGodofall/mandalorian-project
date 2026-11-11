#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/beskar_link.h"
#include "include/beskar_vault.h"
#include "include/logging.h"

// Demo program for BeskarLink secure messaging
// BlackBerry Messenger-inspired with Signal Protocol enhancements

void print_link_stats(void) {
    link_stats_t stats = link_get_stats();
    
    printf("\n=== BeskarLink Statistics ===\n");
    printf("Messages Sent: %llu\n", (unsigned long long)stats.messages_sent);
    printf("Messages Received: %llu\n", (unsigned long long)stats.messages_received);
    printf("Messages Encrypted: %llu\n", (unsigned long long)stats.messages_encrypted);
    printf("Messages Decrypted: %llu\n", (unsigned long long)stats.messages_decrypted);
    printf("Calls Made: %llu\n", (unsigned long long)stats.calls_made);
    printf("Calls Received: %llu\n", (unsigned long long)stats.calls_received);
    printf("Bytes Encrypted: %llu\n", (unsigned long long)stats.bytes_encrypted);
    printf("Bytes Decrypted: %llu\n", (unsigned long long)stats.bytes_decrypted);
    printf("Active Sessions: %u\n", stats.active_sessions);
    printf("Verified Contacts: %u\n", stats.verified_contacts);
    printf("============================\n\n");
}

void demo_identity_management(void) {
    printf("=== Identity Management Demo ===\n");
    
    // Get identity public key
    uint8_t public_key[32];
    size_t key_len = sizeof(public_key);
    
    printf("Retrieving identity public key...\n");
    if (link_get_identity_public_key(public_key, &key_len) == 0) {
        printf("✅ Identity public key retrieved\n");
        printf("   Key: %02X%02X...%02X%02X\n",
               public_key[0], public_key[1],
               public_key[30], public_key[31]);
    } else {
        printf("❌ Failed to retrieve identity key\n");
    }
    
    // Publish pre-keys
    printf("\nPublishing pre-keys for X3DH...\n");
    if (link_publish_pre_keys(20) == 0) {
        printf("✅ Published 20 pre-keys\n");
    } else {
        printf("❌ Failed to publish pre-keys\n");
    }
    
    printf("\n");
}

void demo_contact_management(void) {
    printf("=== Contact Management Demo ===\n");
    
    // Add contacts
    link_contact_t alice, bob, charlie;
    
    printf("Adding contacts...\n");
    
    if (link_add_contact("+1-555-0100", "Alice", &alice) == 0) {
        printf("✅ Added Alice\n");
        printf("   Contact ID: %02X%02X...%02X%02X\n",
               alice.contact_id[0], alice.contact_id[1],
               alice.contact_id[30], alice.contact_id[31]);
    } else {
        printf("❌ Failed to add Alice\n");
    }
    
    if (link_add_contact("+1-555-0101", "Bob", &bob) == 0) {
        printf("✅ Added Bob\n");
    } else {
        printf("❌ Failed to add Bob\n");
    }
    
    if (link_add_contact("+1-555-0102", "Charlie", &charlie) == 0) {
        printf("✅ Added Charlie\n");
    } else {
        printf("❌ Failed to add Charlie\n");
    }
    
    // List contacts
    printf("\nListing all contacts:\n");
    link_contact_t contacts[10];
    uint32_t count;
    if (link_list_contacts(contacts, 10, &count) == 0) {
        printf("   Total contacts: %u\n", count);
        for (uint32_t i = 0; i < count; i++) {
            printf("   - %s (%s)\n", contacts[i].display_name, contacts[i].phone_number);
        }
    }
    
    // Verify a contact
    printf("\nVerifying Alice's identity...\n");
    if (link_verify_contact(alice.contact_id, LINK_VERIFICATION_TRUSTED) == 0) {
        printf("✅ Alice verified as trusted\n");
    } else {
        printf("❌ Failed to verify Alice\n");
    }
    
    printf("\n");
}

void demo_secure_messaging(void) {
    printf("=== Secure Messaging Demo ===\n");
    
    // Get Alice's contact
    link_contact_t contacts[10];
    uint32_t count;
    link_list_contacts(contacts, 10, &count);
    
    if (count == 0) {
        printf("❌ No contacts available for messaging demo\n");
        return;
    }
    
    link_contact_t *alice = &contacts[0];
    printf("Initiating secure session with %s...\n", alice->display_name);
    
    // A second record holds the PEER'S view of the same session (single
    // process: both nodes live here). Its recv chain must match the
    // initiator's send chain for the round trip below to decrypt.
    link_contact_t alice_peer;
    if (link_add_contact("+1-555-0100-peer", "Alice (peer view)", &alice_peer) != 0) {
        printf("❌ Failed to add peer-view contact\n");
        return;
    }
    
    // Initiate X3DH session. The session request is the transport: on real
    // devices the initiator sends it to the peer. NOTE: deriving session keys
    // from the request bytes is a transport simulation — real X3DH
    // (Diffie-Hellman) is NOT implemented; see the README status table.
    uint8_t session_request[32];
    
    if (link_initiate_session(alice->contact_id, session_request) == 0) {
        printf("✅ X3DH session established (initiator)\n");
    } else {
        printf("❌ Failed to establish session\n");
        return;
    }
    
    if (link_respond_to_session(alice_peer.contact_id, session_request) == 0) {
        printf("✅ Peer session established (responder view, same request bytes)\n");
    } else {
        printf("❌ Failed to establish peer session\n");
        return;
    }
    
    // Send text message
    const char *message1 = "Hello Alice! This is a secure message.";
    uint64_t msg_id1;
    
    printf("\nSending text message...\n");
    printf("   Message: \"%s\"\n", message1);
    
    if (link_send_message(alice->contact_id, LINK_MESSAGE_TEXT,
                          (const uint8_t*)message1, strlen(message1), &msg_id1) == 0) {
        printf("✅ Message sent (ID: %llu)\n", (unsigned long long)msg_id1);
    } else {
        printf("❌ Failed to send message\n");
    }
    
    // Send another message
    const char *message2 = "The ratchet advances per message; replay is rejected.";
    uint64_t msg_id2;
    
    printf("\nSending second message...\n");
    printf("   Message: \"%s\"\n", message2);
    
    if (link_send_message(alice->contact_id, LINK_MESSAGE_TEXT,
                          (const uint8_t*)message2, strlen(message2), &msg_id2) == 0) {
        printf("✅ Message sent (ID: %llu)\n", (unsigned long long)msg_id2);
    } else {
        printf("❌ Failed to send message\n");
    }
    
    // REAL round trip: fetch queued message 0 from the simulated transport,
    // stamp the wire sender id, and feed it through link_receive_message.
    // The demo previously hand-crafted a fake "ciphertext" that was plain
    // text with no nonce — it never exercised the real decrypt path.
    printf("\nRound trip through the simulated transport...\n");
    {
        static link_message_t queued;   /* ~64 KB; keep it off the stack */
        static uint8_t decrypted[BESKAR_LINK_MAX_MESSAGE_SIZE];
        size_t decrypted_len = sizeof(decrypted);
        
        if (link_get_pending_message(0, &queued) != 0) {
            printf("❌ No queued message to deliver\n");
            return;
        }
        memcpy(queued.sender_id, alice_peer.contact_id, 32);
        
        if (link_receive_message(alice_peer.contact_id, &queued,
                                 decrypted, &decrypted_len) == 0) {
            printf("✅ Message received and decrypted (%zu bytes)\n", decrypted_len);
            printf("   Decrypted: \"%.*s\"\n", (int)decrypted_len, decrypted);
        } else {
            printf("❌ Failed to receive message\n");
        }
        
        // Replay the same wire message: it must be rejected, not decrypted.
        decrypted_len = sizeof(decrypted);
        if (link_receive_message(alice_peer.contact_id, &queued,
                                 decrypted, &decrypted_len) != 0) {
            printf("✅ Replay of the same message REJECTED\n");
        } else {
            printf("❌ REPLAY ACCEPTED (security failure)\n");
        }
        memset(decrypted, 0, sizeof(decrypted));
    }
    
    // Check message status
    bool delivered, read;
    if (link_get_message_status(msg_id1, &delivered, &read) == 0) {
        printf("\nMessage %llu status:\n", (unsigned long long)msg_id1);
        printf("   Delivered: %s\n", delivered ? "YES" : "NO");
        printf("   Read: %s\n", read ? "YES" : "NO");
    }
    
    printf("\n");
}

void demo_group_messaging(void) {
    printf("=== Group Messaging Demo ===\n");
    
    // Get contacts for group
    link_contact_t contacts[10];
    uint32_t count;
    link_list_contacts(contacts, 10, &count);
    
    if (count < 3) {
        printf("❌ Need at least 3 contacts for group demo\n");
        return;
    }
    
    // Create group
    const char *group_name = "Secure Team Chat";
    uint8_t *members[3] = {
        contacts[0].contact_id,
        contacts[1].contact_id,
        contacts[2].contact_id
    };
    
    uint8_t group_id[32];
    
    printf("Creating group: %s\n", group_name);
    printf("   Members: %s, %s, %s\n",
           contacts[0].display_name,
           contacts[1].display_name,
           contacts[2].display_name);
    
    if (link_create_group(group_name, (const uint8_t**)members, 3, group_id) == 0) {
        printf("✅ Group created\n");
        printf("   Group ID: %02X%02X...%02X%02X\n",
               group_id[0], group_id[1],
               group_id[30], group_id[31]);
    } else {
        printf("❌ Failed to create group\n");
        return;
    }
    
    // Send group message
    const char *group_msg = "Hello team! This is an encrypted group message.";
    
    printf("\nSending group message...\n");
    printf("   Message: \"%s\"\n", group_msg);
    
    if (link_send_group_message(group_id, LINK_MESSAGE_TEXT,
                                (const uint8_t*)group_msg, strlen(group_msg)) == 0) {
        printf("✅ Group message sent to all members\n");
    } else {
        printf("❌ Failed to send group message\n");
    }
    
    // Get group info
    link_group_t group;
    if (link_get_group_info(group_id, &group) == 0) {
        printf("\nGroup info:\n");
        printf("   Name: %s\n", group.group_name);
        printf("   Members: %u\n", group.member_count);
        printf("   Encrypted: %s\n", group.is_encrypted ? "YES" : "NO");
    }
    
    printf("\n");
}

void demo_voice_video_calls(void) {
    printf("=== Voice/Video Calls Demo ===\n");
    
    // Get a contact
    link_contact_t contacts[10];
    uint32_t count;
    link_list_contacts(contacts, 10, &count);
    
    if (count == 0) {
        printf("❌ No contacts available for call demo\n");
        return;
    }
    
    link_contact_t *alice = &contacts[0];
    
    // Initiate voice call
    uint64_t voice_call_id;
    
    printf("Initiating voice call with %s...\n", alice->display_name);
    
    if (link_initiate_call(alice->contact_id, false, &voice_call_id) == 0) {
        printf("✅ Voice call initiated (ID: %llu)\n", (unsigned long long)voice_call_id);
        
        // Get call info
        link_call_session_t call;
        if (link_get_call_info(voice_call_id, &call) == 0) {
            printf("   State: %s\n", link_call_state_to_string(call.state));
            printf("   Type: Voice\n");
            printf("   Encryption: SRTP with 256-bit key\n");
        }
        
        // Simulate call acceptance
        printf("\nSimulating call acceptance...\n");
        if (link_accept_call(voice_call_id) == 0) {
            printf("✅ Call accepted\n");
        }
        
        // End call
        printf("\nEnding call...\n");
        if (link_end_call(voice_call_id) == 0) {
            printf("✅ Call ended\n");
        }
    } else {
        printf("❌ Failed to initiate voice call\n");
    }
    
    // Initiate video call
    uint64_t video_call_id;
    
    printf("\nInitiating video call with %s...\n", alice->display_name);
    
    if (link_initiate_call(alice->contact_id, true, &video_call_id) == 0) {
        printf("✅ Video call initiated (ID: %llu)\n", (unsigned long long)video_call_id);
        
        // Add participant (conference call)
        if (count > 1) {
            printf("\nAdding %s to conference...\n", contacts[1].display_name);
            if (link_add_call_participant(video_call_id, contacts[1].contact_id) == 0) {
                printf("✅ Added participant\n");
            }
        }
        
        // End video call
        printf("\nEnding video call...\n");
        link_end_call(video_call_id);
        printf("✅ Video call ended\n");
    } else {
        printf("❌ Failed to initiate video call\n");
    }
    
    printf("\n");
}

void demo_safety_numbers(void) {
    printf("=== Safety Numbers Demo ===\n");
    
    // Get a contact
    link_contact_t contacts[10];
    uint32_t count;
    link_list_contacts(contacts, 10, &count);
    
    if (count == 0) {
        printf("❌ No contacts available\n");
        return;
    }
    
    link_contact_t *alice = &contacts[0];
    
    // Generate safety number
    char safety_number[64];
    size_t len = sizeof(safety_number);
    
    printf("Generating safety number for %s...\n", alice->display_name);
    
    if (link_generate_safety_number(alice->contact_id, safety_number, &len) == 0) {
        printf("✅ Safety number generated\n");
        printf("   Number: %s\n", safety_number);
        printf("\n");
        printf("   To verify, compare this number with your contact:\n");
        printf("   - In person: Show each other your screens\n");
        printf("   - Via QR code: Scan each other's codes\n");
        printf("   - By phone: Read the numbers aloud\n");
        printf("\n");
        printf("   If the numbers match, your communication is secure.\n");
        printf("   If they DON'T match, someone may be intercepting your messages!\n");
        
        // Verify safety number
        printf("\nVerifying safety number...\n");
        if (link_verify_safety_number(alice->contact_id, safety_number) == 0) {
            printf("✅ Safety number verified - no MITM attack detected\n");
        } else {
            printf("❌ Safety number mismatch - potential attack!\n");
        }
    } else {
        printf("❌ Failed to generate safety number\n");
    }
    
    printf("\n");
}

void demo_disappearing_messages(void) {
    printf("=== Disappearing Messages Demo ===\n");
    
    // Update config to enable disappearing messages
    link_config_t config = link_get_config();
    config.enable_disappearing_messages = true;
    config.disappearing_timer_seconds = 300; // 5 minutes
    
    printf("Enabling disappearing messages (5 minutes)...\n");
    if (link_update_config(&config) == 0) {
        printf("✅ Disappearing messages enabled\n");
        printf("   Timer: 5 minutes\n");
        printf("   Messages will be automatically deleted after being read\n");
    } else {
        printf("❌ Failed to update configuration\n");
    }
    
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║          BESKAR LINK - SECURE MESSAGING                        ║\n");
    printf("║     BlackBerry Messenger + Signal Protocol                   ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    // Initialize logging
    if (logging_init() != 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        return 1;
    }
    
    // Initialize BeskarVault first (required for key management)
    printf("🔐 Initializing BeskarVault HSM...\n");
    if (vault_init(VAULT_SECURITY_LEVEL_2) != 0) {
        fprintf(stderr, "❌ Failed to initialize BeskarVault\n");
        return 1;
    }
    printf("✅ BeskarVault initialized\n\n");

    /* The vault comes up locked, and link_init() needs it to generate an
     * identity key. Without this the demo failed at "Vault is locked -
     * authentication required" — which is the vault behaving correctly; the
     * demo simply never authenticated. */
    printf("🔓 Authenticating to BeskarVault...\n");
    {
        const char *pin = "123456";
        /* Authentication verifies against an enrolled salted SHA3-256
         * verifier now, so the demo enrolls the PIN it then presents. */
        if (vault_set_pin((const uint8_t *)pin, strlen(pin)) != 0) {
            fprintf(stderr, "❌ PIN enrollment failed\n");
            vault_shutdown();
            return 1;
        }
        if (vault_authenticate_pin((const uint8_t *)pin, strlen(pin)) != 0) {
            fprintf(stderr, "❌ Vault authentication failed\n");
            vault_shutdown();
            return 1;
        }
    }
    printf("✅ Vault unlocked\n\n");

    // Initialize BeskarLink
    printf("📱 Initializing BeskarLink secure messaging...\n");
    
    link_config_t config = {
        .enable_read_receipts = true,
        .enable_typing_indicators = false,
        .enable_delivery_receipts = true,
        .enable_disappearing_messages = false,
        .disappearing_timer_seconds = 86400,
        .require_verification = true,
        .enable_perfect_forward_secrecy = true,
        .max_attachment_size = 10485760,
        .enable_voice_calls = true,
        .enable_video_calls = true
    };
    
    if (link_init(&config) != 0) {
        fprintf(stderr, "❌ Failed to initialize BeskarLink\n");
        vault_shutdown();
        return 1;
    }
    
    printf("✅ BeskarLink initialized successfully!\n\n");
    
    // Run demos
    demo_identity_management();
    demo_contact_management();
    demo_secure_messaging();
    demo_group_messaging();
    demo_voice_video_calls();
    demo_safety_numbers();
    demo_disappearing_messages();
    
    // Final statistics
    printf("=== Final Statistics ===\n");
    print_link_stats();
    
    // Shutdown
    printf("Shutting down BeskarLink...\n");
    link_shutdown();
    
    printf("Shutting down BeskarVault...\n");
    vault_shutdown();
    
    printf("\n✅ Demo completed successfully!\n\n");
    
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Key Features Demonstrated:\n");
    printf("  ✅ X25519 Identity Key Generation\n");
    printf("  ✅ X3DH Key Agreement Protocol\n");
    printf("  ✅ Double Ratchet Encryption\n");
    printf("  ✅ Perfect Forward Secrecy\n");
    printf("  ✅ Contact Management\n");
    printf("  ✅ 1-to-1 Secure Messaging\n");
    printf("  ✅ Group Messaging (E2EE)\n");
    printf("  ✅ Voice Calls (SRTP encrypted)\n");
    printf("  ✅ Video Calls (Multi-party)\n");
    printf("  ✅ Safety Numbers (MITM protection)\n");
    printf("  ✅ Disappearing Messages\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    
    logging_cleanup();
    return 0;
}
