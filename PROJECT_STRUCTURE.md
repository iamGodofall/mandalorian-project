# Mandalorian Project Structure

```
d:/mandalorian-project/
├── TODO.md
├── aegis/
│   ├── include/
│   │   └── aegis.h
│   └── src/
│       └── monitor.c
├── beskarcore/
│   ├── demo.c
│   ├── demo.exe
│   ├── LICENSE
│   ├── Makefile
│   ├── README.md
│   ├── CAmkES/
│   │   ├── system.camkes
│   │   └── components/
│   │       ├── boot_rom.camkes
│   │       ├── dummy_app.camkes
│   │       └── shield_ledger.camkes
│   ├── seL4/
│   │   ├── .cmake-format.yaml
│   │   ├── .gitignore
│   │   ├── CAVEATS.md
│   │   ├── CHANGES.md
│   │   ├── CMakeLists.txt
│   │   ├── CODE_OF_CONDUCT.md
│   │   ├── config.cmake
│   │   ├── CONTRIBUTING.md
│   │   ├── CONTRIBUTORS.md
│   │   ├── FindseL4.cmake
│   │   ├── gcc.cmake
│   │   ├── gdb-macros
│   │   ├── LICENSE.md
│   │   ├── llvm.cmake
│   │   ├── README.md
│   │   ├── SECURITY.md
│   │   ├── VERSION
│   │   ├── configs/
│   │   │   ├── AARCH64_bcm2711_verified.cmake
│   │   │   ├── AARCH64_hikey_verified.cmake
│   │   │   ├── AARCH64_imx8mm_verified.cmake
│   │   │   ├── AARCH64_imx8mq_verified.cmake
│   │   │   ├── AARCH64_imx93_verified.cmake
│   │   │   ├── AARCH64_maaxboard_verified.cmake
│   │   │   ├── AARCH64_odroidc2_verified.cmake
│   │   │   ├── AARCH64_odroidc4_verified.cmake
│   │   │   ├── AARCH64_rockpro64_verified.cmake
│   │   │   ├── AARCH64_tqma_verified.cmake
│   │   │   ├── AARCH64_tx1_verified.cmake
│   │   │   ├── AARCH64_ultra96v2_verified.cmake
│   │   │   ├── AARCH64_verified.cmake
│   │   │   ├── AARCH64_zynqmp_verified.cmake
│   │   │   ├── ARM_am335x_verified.cmake
│   │   │   ├── ARM_bcm2837_verified.cmake
│   │   │   ├── ARM_exynos4_verified.cmake
│   │   │   ├── ARM_exynos5410_verified.cmake
│   │   │   ├── ARM_exynos5422_verified.cmake
│   │   │   ├── ARM_hikey_verified.cmake
│   │   │   ├── ARM_HYP_exynos5_verified.cmake
│   │   │   ├── ARM_HYP_exynos5410_verified.cmake
│   │   │   ├── ARM_HYP_verified.cmake
│   │   │   ├── ARM_imx8mm_verified.cmake
│   │   │   ├── ARM_MCS_verified.cmake
│   │   │   ├── ARM_omap3_verified.cmake
│   │   │   ├── ARM_tk1_verified.cmake
│   │   │   ├── ARM_verified.cmake
│   │   │   ├── ARM_zynq7000_verified.cmake
│   │   │   ├── ARM_zynqmp_verified.cmake
│   │   │   ├── RISCV64_MCS_verified.cmake
│   │   │   ├── RISCV64_verified.cmake
│   │   │   ├── seL4Config.cmake
│   │   │   ├── X64_verified.cmake
│   │   │   └── include/
│   │   ├── include/
│   │   │   ├── api.h
│   │   │   ├── assert.h
│   │   │   ├── basic_types.h
│   │   │   ├── bootinfo.h
│   │   │   ├── compound_types.h
│   │   │   ├── config.h
│   │   │   ├── hardware.h
│   │   │   ├── linker.h
│   │   │   ├── machine.h
│   │   │   ├── object.h
│   │   │   ├── stdarg.h
│   │   │   ├── stdint.h
│   │   │   ├── string.h
│   │   │   ├── types.h
│   │   │   └── util.h
│   │   ├── 32/
│   │   ├── 64/
│   │   ├── api/
│   │   ├── arch/
│   │   ├── benchmark/
│   │   ├── drivers/
│   │   ├── fastpath/
│   │   ├── kernel/
│   │   ├── machine/
│   │   ├── model/
│   │   ├── object/
│   │   ├── plat/
│   │   ├── smp/
│   │   ├── libsel4/
│   │   │   ├── CMakeLists.txt
│   │   │   ├── arch_include/
│   │   │   ├── include/
│   │   │   ├── mode_include/
│   │   │   ├── sel4_arch_include/
│   │   │   ├── sel4_plat_include/
│   │   │   └── src/
│   │   ├── LICENSES/
│   │   │   ├── Apache-2.0.txt
│   │   │   ├── BSD-2-Clause.txt
│   │   │   ├── BSD-3-Clause.txt
│   │   │   ├── CC-BY-SA-4.0.txt
│   │   │   ├── GPL-2.0-only.txt
│   │   │   ├── GPL-2.0-or-later.txt
│   │   │   ├── LicenseRef-Trademark.txt
│   │   │   ├── LPPL-1.3c.txt
│   │   │   ├── MIT.txt
│   │   │   └── SHL-0.51.txt
│   │   ├── manual/
│   │   │   ├── Doxyfile
│   │   │   ├── export.bst
│   │   │   ├── extra.bib
│   │   │   ├── Makefile
│   │   │   ├── manual.tex
│   │   │   ├── README.md
│   │   │   ├── references.bib
│   │   │   ├── sel4.sty
│   │   │   ├── VERSION
│   │   │   ├── figs/
│   │   │   ├── logos/
│   │   │   ├── parts/
│   │   │   └── tools/
│   │   ├── src/
│   │   │   ├── assert.c
│   │   │   ├── config.cmake
│   │   │   ├── inlines.c
│   │   │   ├── string.c
│   │   │   ├── util.c
│   │   │   ├── api/
│   │   │   ├── arch/
│   │   │   ├── benchmark/
│   │   │   ├── config/
│   │   │   ├── drivers/
│   │   │   ├── fastpath/
│   │   │   ├── kernel/
│   │   │   ├── machine/
│   │   │   ├── model/
│   │   │   ├── object/
│   │   │   ├── plat/
│   │   │   └── smp/
│   │   └── tools/
│   │       ├── bf.vim
│   │       ├── bitfield_gen.md
│   │       ├── bitfield_gen.py
│   │       ├── changed.sh
│   │       ├── circular_includes.py
│   │       ├── condition.py
│   │       ├── config_gen.py
│   │       ├── cpp_gen.sh
│   │       ├── flags.cmake
│   │       ├── hardware_gen.py
│   │       ├── hardware_schema.yml
│   │       ├── hardware.yml
│   │       ├── helpers.cmake
│   │       ├── internal.cmake
│   │       ├── invocation_header_gen.py
│   │       ├── invocation_json_gen.py
│   │       ├── kernel_pylint.sh
│   │       ├── kernel_xmllint.sh
│   │       ├── lex.py
│   │       ├── dts/
│   │       └── hardware/
│   └── src/
│       ├── dummy_app.c
│       ├── merkle_ledger.c
│       └── verified_boot.c
├── docs/
│   └── fosdem2026_talk_outline.md
├── hardware/
│   └── flash_visionfive2.sh
├── mandate/
│   └── PRODUCT_BRIEF.md
└── veridianos/
    ├── demo.c
    ├── README.md
    ├── include/
    │   └── u_runtime.h
    ├── openswiftui/
    │   └── SPEC.md
    ├── src/
    │   ├── android_runtime.c
    │   ├── app_sandbox.c
    │   └── u_runtime.c
    ├── tools/
    │   └── veridian-rebuild-ios
    └── waydroid/
        └── HARDENING.md
