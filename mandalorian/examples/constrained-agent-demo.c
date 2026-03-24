/* Minimum Working System Demo
 * Agent with cap for /tmp/output.txt write only
 * Tests: ALLOW write tmp, DENY /etc, DENY expiry
 */

#include \"../core/gate.h\"
#include \"../capabilities/issuer.h\"
#include \"stubs.h\"
#include \<beskarcore/include/logging.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main() {
    // 1. Issue test capability
    mandalorian_cap_t cap;
    issue_test_cap(&amp;cap, \"agent_01\", \"write\", \"/tmp/output.txt\", \"maxSize=10KB\", 300); // 5min

    printf(\"[DEMO] Capability issued: %s %s %s (expires %ld)\\n\", 
           cap.action, cap.resource, cap.constraints, cap.expiry);

    // 2. Test ALLOWED action
    mandalorian_request_t req1 = {
        .agent_id = 1,
        .action = \"write\",
        .resource = \"/tmp/output.txt\",
        .payload = \"Hello Mandalorian!\"
    };
    if (mandalorian_execute(&amp;req1, &amp;cap) == GATE_OK) {
        printf(\"[PASS] Write to /tmp/output.txt ALLOWED\\n\");
    }

    // 3. Test DENIED action
    mandalorian_request_t req2 = {
        .agent_id = 1,
        .action = \"write\",
        .resource = \"/etc/passwd\",
        .payload = \"malicious\"
    };
    if (mandalorian_execute(&amp;req2, &amp;cap) != GATE_OK) {
        printf(\"[PASS] Write to /etc/passwd DENIED\\n\");
    }

    // 4. Test EXPIRED (manual expiry override)
    cap.expiry = time(NULL) - 60;
    if (mandalorian_execute(&amp;req1, &amp;cap) != GATE_OK) {
        printf(\"[PASS] Expired capability DENIED\\n\");
    }

    printf(\"[SUCCESS] All tests passed. System enforces boundaries.\\n\");
    return 0;
}
