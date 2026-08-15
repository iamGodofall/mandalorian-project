/**
 * @file boot_rom.c
 * @brief Boot ROM CAmkES component — first link in the measured boot chain.
 *
 * This file previously contained nothing but a list of #includes and an
 * unresolved merge conflict marker, so the component declared in
 * CAmkES/components/boot_rom.camkes had no implementation at all.
 *
 * What it does now is deliberately modest and matches what the code can
 * actually back: it initialises verified boot, measures the chain, and records
 * the measurement in the Shield Ledger. It does NOT implement hardware root of
 * trust, OTP key fusing, or tamper response — those need custom silicon, as
 * the README's hardware reality check already states.
 */

#include "verified_boot.h"

#include <string.h>

#include "error_recovery.h"
#include "logging.h"
#include "merkle_ledger.h"
#include "monitoring.h"
#include "performance.h"
#include "sha3.h"

/* Measured-boot configuration for the simulation/dev target. Secure boot is
 * off because there is no hardware root of trust to anchor it to; claiming
 * otherwise here would be the kind of thing the transparency clause in the
 * licence exists to prevent. */
static const boot_config_t boot_rom_config = {
    .enable_secure_boot = 0,
    .enable_measured_boot = 1,
    .enable_remote_attestation = 0,
    .root_certificate_path = NULL,
    .boot_log_path = NULL,
};

/**
 * @brief Run the boot ROM sequence.
 *
 * @return BOOT_SUCCESS when the chain verified and was logged, otherwise the
 *         first failing step's error code.
 */
int boot_rom_run(void)
{
    uint8_t measurement[SHA3_256_DIGEST_SIZE];
    size_t measurement_len = sizeof(measurement);
    int rc;

    LOG_INFO("Boot ROM: starting measured boot");

    rc = boot_init(&boot_rom_config);
    if (rc != BOOT_SUCCESS) {
        LOG_ERROR("Boot ROM: init failed: %s", boot_error_to_string(rc));
        return rc;
    }

    rc = boot_verify_chain();
    if (rc != BOOT_SUCCESS) {
        LOG_ERROR("Boot ROM: chain verification failed: %s",
                  boot_error_to_string(rc));
        return rc;
    }

    rc = boot_get_measurement(measurement, &measurement_len);
    if (rc != BOOT_SUCCESS) {
        LOG_ERROR("Boot ROM: could not read measurement: %s",
                  boot_error_to_string(rc));
        return rc;
    }

    /* Anchor the measurement in the ledger before handing control on, so a
     * later component cannot retroactively deny what booted. */
    if (add_ledger_entry("BOOT_ROM_MEASUREMENT", measurement) != 0) {
        LOG_ERROR("Boot ROM: failed to record measurement in Shield Ledger");
        return BOOT_ERROR_CHAIN_BROKEN;
    }

    LOG_INFO("Boot ROM: chain verified, measurement anchored");
    return BOOT_SUCCESS;
}

/**
 * @brief CAmkES component entry point.
 *
 * CAmkES calls run() once the component's interfaces are up.
 */
int run(void)
{
    return boot_rom_run();
}
