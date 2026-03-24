// OpenClaw Adapter - Transforms agent tool calls to gated requests
// OpenClaw NEVER calls system directly

#include \"../core/gate.h\"
#include \"../../capabilities/issuer.h\"
#include <beskarcore/include/logging.h>
#include <string.h>

gate_result_t adapter_tool_write(const char *path, const char *data, mandalorian_cap_t *cap) {
    mandalorian_request_t req = {
        .agent_id = 1, // From OpenClaw context
        .action = \"write\",
        .resource = (char*)path,
        .payload = (char*)data
    };
    return mandalorian_execute(&amp;req, cap);
}

// e.g. OpenClaw calls this wrapper instead of direct fs_write()

