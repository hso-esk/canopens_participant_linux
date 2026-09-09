# /*
#  * Copyright (c) 2026
#  *
#  * Hochschule Offenburg, University of Applied Sciences
#  * Institute for reliable Embedded Systems
#  * and Communications Electronic (ivESK)
#  *
#  * This file is licensed as described in the "LICENSE" file
#  * included within the root folder of this work.
#  */

cmake_minimum_required(VERSION 3.19)

# Compatibility shim for mbedTLS 2.28 submodule
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

project(spsec_participant VERSION 1.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Default build type: RelWithDebInfo
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
endif()

# Platform selection: linux (default) or lpc55s16
set(SPSEC_PLATFORM "linux" CACHE STRING "Target platform (linux|lpc55s16)")
set_property(CACHE SPSEC_PLATFORM PROPERTY STRINGS "linux" "lpc55s16")

string(TOLOWER "${SPSEC_PLATFORM}" spsec_platform_lower)

if(NOT (spsec_platform_lower STREQUAL "linux" OR spsec_platform_lower STREQUAL "lpc55s16"))
    message(FATAL_ERROR "Unsupported SPSEC_PLATFORM: ${SPSEC_PLATFORM} (use linux or lpc55s16)")
endif()

message(STATUS "Target platform: ${spsec_platform_lower}")

# Platform-specific configuration
if(spsec_platform_lower STREQUAL "lpc55s16")
    # Bare metal: no pthreads, no stdio filesystem, no POSIX
    set(PLATFORM_BAREMETAL 1)
    set(SPSEC_DEFINES
        SDK_OS_BAREMETAL
        LPC55_SERIES
        SPSEC_PLATFORM_LPC55S16
    )
    # Toolchain file should set CMAKE_C_COMPILER, CMAKE_SYSTEM_NAME=Generic, etc.
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU" AND NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
        message(WARNING "LPC55S16 build expects GCC or Clang cross-compiler")
    endif()
    # No pthread for baremetal
    set(PLATFORM_LIBS "")
    # Linker script, startup code, etc. provided by SDK
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --specs=nano.specs --specs=nosys.specs")
else()
    # Linux: POSIX, pthreads, filesystem
    set(PLATFORM_BAREMETAL 0)
    set(SPSEC_DEFINES "")
    set(PLATFORM_LIBS pthread)
endif()

# Base compiler flags
set(COMMON_C_FLAGS "-Wall -Wextra -Wpedantic -g")
if(spsec_platform_lower STREQUAL "linux")
    set(COMMON_C_FLAGS "${COMMON_C_FLAGS} -O0 -pthread")
else()
    set(COMMON_C_FLAGS "${COMMON_C_FLAGS} -O2 -ffunction-sections -fdata-sections")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_C_FLAGS}")

# Additional warning flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat=2 -Wformat-security")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wstrict-overflow=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wnull-dereference")
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    # -Warray-bounds=2 is GCC-only; Clang rejects the leveled form
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Warray-bounds=2")
endif()

# Hardening (Linux only - PIE/RELRO are ELF-loader concepts that don't
# apply to the bare-metal lpc55s16 static image).
if(spsec_platform_lower STREQUAL "linux")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -fstack-protector-strong")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro,-z,now")
endif()

# Enable -Werror for CI builds
option(WERROR "Treat warnings as errors" OFF)
option(SPSEC_LOG_SECRETS "Enable logging of secret material (keys, salts, plaintext) - DEBUG ONLY" OFF)
if(WERROR)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
    message(STATUS "Warnings as errors: ENABLED")
else()
    message(STATUS "Warnings as errors: DISABLED (use -DWERROR=ON to enable)")
endif()
if(SPSEC_LOG_SECRETS)
    add_compile_definitions(SPSEC_LOG_SECRETS=1)
    message(STATUS "Secret logging: ENABLED (DEBUG BUILD ONLY!)")
else()
    message(STATUS "Secret logging: DISABLED (production safe)")
endif()

# Sanitizer support (Linux only)
if(spsec_platform_lower STREQUAL "linux")
    set(SANITIZE "" CACHE STRING "Enable sanitizers (address|undefined|memory|thread)")
    if(SANITIZE)
        if(SANITIZE STREQUAL "address")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
            message(STATUS "AddressSanitizer: ENABLED")
        elseif(SANITIZE STREQUAL "undefined")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined -fno-omit-frame-pointer")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined -lstdc++")
            message(STATUS "UndefinedBehaviorSanitizer: ENABLED")
        elseif(SANITIZE STREQUAL "address,undefined" OR SANITIZE STREQUAL "undefined,address")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address,undefined -fno-omit-frame-pointer")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined -lstdc++")
            message(STATUS "AddressSanitizer + UndefinedBehaviorSanitizer: ENABLED")
        elseif(SANITIZE STREQUAL "memory")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=memory -fno-omit-frame-pointer")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=memory")
            message(STATUS "MemorySanitizer: ENABLED")
        elseif(SANITIZE STREQUAL "thread")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
            message(STATUS "ThreadSanitizer: ENABLED")
        else()
            message(FATAL_ERROR "Unknown SANITIZE value '${SANITIZE}' (use address|undefined|address,undefined|memory|thread)")
        endif()
    endif()

    # Code coverage (Linux only)
    option(SPSEC_COVERAGE "Enable gcov/lcov coverage instrumentation" OFF)
    if(SPSEC_COVERAGE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -O0 -g")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
        message(STATUS "Coverage instrumentation: ENABLED (gcov/lcov)")
    endif()
endif()

# Generate compile_commands.json for clang-tidy and other tools
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─────────────────────────────────────────────────────────────────────────────
# Salt length selection (common/include/keys.h)
# ─────────────────────────────────────────────────────────────────────────────
set(SPSEC_SALT_LEN "8" CACHE STRING "Pre-shared salt length in bytes (8|12)")
set_property(CACHE SPSEC_SALT_LEN PROPERTY STRINGS "8" "12")
if(NOT SPSEC_SALT_LEN MATCHES "^(8|12)$")
    message(FATAL_ERROR "Unsupported SPSEC_SALT_LEN: ${SPSEC_SALT_LEN} (use 8 or 12)")
endif()
add_compile_definitions(SALT_LEN=${SPSEC_SALT_LEN})
message(STATUS "Salt length: ${SPSEC_SALT_LEN} bytes")

# ─────────────────────────────────────────────────────────────────────────────
# Crypto backend selection
# ─────────────────────────────────────────────────────────────────────────────
set(SPSEC_CRYPTO_BACKEND "wolfssl" CACHE STRING "Crypto backend to use (mbedtls|wolfssl)")
set_property(CACHE SPSEC_CRYPTO_BACKEND PROPERTY STRINGS "mbedtls" "wolfssl")

string(TOLOWER "${SPSEC_CRYPTO_BACKEND}" spsec_crypto_backend_lower)

set(SPSEC_BACKEND_SOURCES "")
set(SPSEC_BACKEND_LIBS "")
set(SPSEC_BACKEND_DEFINES "")

# Configure mbedTLS build options before add_subdirectory
set(ENABLE_TESTING OFF CACHE BOOL "Enable testing" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "Enable programs" FORCE)
set(BUILD_MBEDTLS_LIBRARY OFF CACHE BOOL "Build TLS library" FORCE)
set(BUILD_MBEDX509_LIBRARY OFF CACHE BOOL "Build X.509 library" FORCE)
set(BUILD_MBEDCRYPTO_LIBRARY ON CACHE BOOL "Build crypto library" FORCE)

# Ensure submodule exists before building
function(spsec_require_submodule _dir)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_dir}/CMakeLists.txt")
        message(FATAL_ERROR
            "Submodule '${_dir}' is missing or empty.\n"
            "This repository vendors its crypto backend as a git submodule. Run:\n"
            "    git submodule update --init --recursive\n"
            "and re-run cmake. (Selected backend: ${SPSEC_CRYPTO_BACKEND})")
    endif()
endfunction()

if(spsec_crypto_backend_lower STREQUAL "mbedtls")
    set(SPSEC_ENABLE_MBEDTLS ON)
    spsec_require_submodule(external/mbedtls)
    add_subdirectory(external/mbedtls EXCLUDE_FROM_ALL)
    # Disable strict conversion warnings and -Werror for external mbedTLS library
    if(TARGET mbedcrypto)
        target_compile_options(mbedcrypto PRIVATE -Wno-sign-conversion -Wno-conversion -Wno-strict-overflow -Wno-error=null-dereference)
        set_target_properties(mbedcrypto PROPERTIES COMPILE_FLAGS "-Wno-error")
    endif()
    set(SPSEC_BACKEND_SOURCES
        common/crypto_backend_mbedtls.c
        common/crypto_rng_mbedtls.c
        common/crypto_kdf_mbedtls.c
        common/crypto_kdf_registry.c)
    set(SPSEC_BACKEND_LIBS mbedcrypto)
    set(SPSEC_BACKEND_DEFINES SPSEC_ENABLE_MBEDTLS)

elseif(spsec_crypto_backend_lower STREQUAL "wolfssl")
    set(SPSEC_ENABLE_WOLFSSL ON)
    set(WOLFSSL_EXAMPLES "no" CACHE STRING "Enable examples (default: enabled)" FORCE)
    set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "Enable Crypt Bench/Test (default: enabled)" FORCE)
    set(WOLFSSL_CRYPT_TESTS_LIBS "no" CACHE STRING "Build static libraries from the wolfCrypt test and benchmark sources (default: disabled)" FORCE)
    if(PLATFORM_BAREMETAL)
        # No pthreads on bare metal - keep wolfSSL out of HAVE_PTHREAD/THREAD_TYPE.
        set(WOLFSSL_SINGLE_THREADED "yes" CACHE STRING "Enable wolfSSL single threaded" FORCE)
    endif()
    spsec_require_submodule(external/wolfssl)
    add_subdirectory(external/wolfssl EXCLUDE_FROM_ALL)
    if(TARGET wolfssl)
        target_compile_definitions(wolfssl PUBLIC WOLFSSL_USER_SETTINGS)
        target_include_directories(wolfssl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common/include)
        if(PLATFORM_BAREMETAL)
            # No POSIX filesystem (opendir/readdir/DIR) on bare metal.
            # Both defines are needed: NO_FILESYSTEM skips wc_FileLoad's
            # dirent.h include, but ReadDirCtx's DIR* member is gated
            # separately on NO_WOLFSSL_DIR (see wolfcrypt/wc_port.h).
            target_compile_definitions(wolfssl PUBLIC NO_FILESYSTEM NO_WOLFSSL_DIR)
        endif()
        # wolfSSL ASCON source path
        set(_spsec_ascon_src
            ${CMAKE_CURRENT_SOURCE_DIR}/external/wolfssl/wolfcrypt/src/ascon.c)
        if(NOT EXISTS "${_spsec_ascon_src}")
            message(FATAL_ERROR "wolfSSL Ascon source not found at ${_spsec_ascon_src}")
        endif()
        target_sources(wolfssl PRIVATE ${_spsec_ascon_src})
        # Compiler warning suppressions for external wolfssl
        target_compile_options(wolfssl PRIVATE -Wno-strict-overflow -Wno-pedantic)
    endif()
    set(SPSEC_BACKEND_SOURCES
            common/crypto_backend_wolfssl.c
            common/crypto_rng_wolfssl.c
            common/crypto_kdf_wolfssl.c
            common/crypto_kdf_registry.c)
    set(SPSEC_BACKEND_LIBS wolfssl::wolfssl)
    set(SPSEC_BACKEND_DEFINES
        SPSEC_ENABLE_WOLFSSL
        WOLFSSL_EXPERIMENTAL_SETTINGS
        HAVE_ASCON
        WOLFSSL_ASCON
        WOLFSSL_MIN_AUTH_TAG_SZ=8)

else()
    message(FATAL_ERROR "Unsupported SPSEC_CRYPTO_BACKEND value: ${SPSEC_CRYPTO_BACKEND}")
endif()

message(STATUS "Configuring crypto backend: ${spsec_crypto_backend_lower}")

# ─────────────────────────────────────────────────────────────────────────────
# Include directories
# ─────────────────────────────────────────────────────────────────────────────
if(SPSEC_ENABLE_MBEDTLS)
    include_directories(${CMAKE_SOURCE_DIR}/external/mbedtls/include)
endif()
if(SPSEC_ENABLE_WOLFSSL)
    include_directories(${CMAKE_SOURCE_DIR}/external/wolfssl)
endif()
# Include directories
include_directories(${CMAKE_SOURCE_DIR}/common/hal/include)
include_directories(${CMAKE_SOURCE_DIR}/common/include)
include_directories(${CMAKE_SOURCE_DIR}/platform)
include_directories(${CMAKE_SOURCE_DIR}/spsec_participant/include)
include_directories(${CMAKE_SOURCE_DIR}/spsec_can_protocol/include)

# ─────────────────────────────────────────────────────────────────────────────
# Source files
# ─────────────────────────────────────────────────────────────────────────────
set(COMMON_SOURCES
    common/spsec_common.c
    common/spsec_errors.c
    common/config.c
    common/crypto.c
    common/crypto_backend_registry.c
    common/crypto_kdf.c
    common/crypto_kdf_registry.c
    common/keys.c
    common/messages_core.c
    common/messages_handshake.c
    common/messages_session.c
    common/messages_register.c
    common/hal/nvol_storage.c
    common/hal/nvol_storage_file.c
    common/hal/nvol_storage_registry.c
)

# Platform sources selected by target
if(spsec_platform_lower STREQUAL "linux")
    set(PLATFORM_SOURCES
        platform/can_interface.c
        platform/logging.c
        platform/randomgen.c
        platform/timer.c
        platform/nvol_storage.c
        platform/led_status.c
        platform/device_info.c
        platform/can_bitrate.c
        platform/dll_events.c
        platform/system.c
    )
elseif(spsec_platform_lower STREQUAL "lpc55s16")
    set(PLATFORM_SOURCES
        platform/lpc55s16/can_interface.c
        platform/lpc55s16/logging.c
        platform/lpc55s16/randomgen.c
        platform/lpc55s16/timer.c
        platform/lpc55s16/led_status.c
        platform/lpc55s16/device_info.c
        platform/lpc55s16/can_bitrate.c
        platform/lpc55s16/dll_events.c
        platform/lpc55s16/system.c
    )
    # LPC55S16 needs MCUXpresso SDK includes
    if(DEFINED ENV{MCUX_SDK_PATH})
        include_directories($ENV{MCUX_SDK_PATH}/devices/LPC55S16)
        include_directories($ENV{MCUX_SDK_PATH}/devices/LPC55S16/drivers)
        include_directories($ENV{MCUX_SDK_PATH}/CMSIS)
    else()
        message(WARNING "MCUX_SDK_PATH not set — LPC55S16 build will fail without SDK headers")
    endif()
endif()

set(PARTICIPANT_SOURCES
    spsec_participant/participant_keys.c
    spsec_participant/participant_state.c
    spsec_participant/participant.c
    spsec_participant/participant_lifecycle.c
    spsec_participant/participant_storage.c
    spsec_participant/register_operations.c
    spsec_participant/register_validation.c
    spsec_participant/register_write_apply.c
    spsec_participant/register_write_init.c
    spsec_participant/register_write_segment.c
    spsec_participant/register_read_init.c
    spsec_participant/register_read_segment.c
    spsec_participant/configuration_loop.c
    spsec_participant/session_appdata.c
    spsec_participant/session_crypto.c
    spsec_participant/session_handshake.c
    spsec_participant/session_heartbeat.c
    spsec_participant/session_loop_waiting.c
    spsec_participant/session_loop_secure.c
    spsec_participant/session_loop_warning.c
    spsec_participant/session_loops_common.c
    spsec_participant/session_timesync.c
    spsec_participant/internal_events.c
)

# Protocol and application sources
set(PROJECT_SOURCES
    src/participant_can.c
    spsec_can_protocol/spsec_protocol_can.c
    spsec_can_protocol/protocol_handshake.c
    spsec_can_protocol/protocol_session.c
    spsec_can_protocol/protocol_register.c
    spsec_can_protocol/participant_channel_can.c
)

# ─────────────────────────────────────────────────────────────────────────────
# Core static library (shared by the binary and the unit tests)
# ─────────────────────────────────────────────────────────────────────────────
add_library(spsec_core STATIC
    ${COMMON_SOURCES}
    ${SPSEC_BACKEND_SOURCES}
    ${PLATFORM_SOURCES}
    ${PARTICIPANT_SOURCES}
    ${PROJECT_SOURCES}
)
target_link_libraries(spsec_core PUBLIC ${SPSEC_BACKEND_LIBS} ${PLATFORM_LIBS})
if(SPSEC_BACKEND_DEFINES)
    target_compile_definitions(spsec_core PUBLIC ${SPSEC_BACKEND_DEFINES})
endif()
if(SPSEC_DEFINES)
    target_compile_definitions(spsec_core PUBLIC ${SPSEC_DEFINES})
endif()
# Apply stricter warnings only to project code, not external libraries
target_compile_options(spsec_core PRIVATE -Wsign-conversion -Wconversion)

# ─────────────────────────────────────────────────────────────────────────────
# Executable target(s)
# ─────────────────────────────────────────────────────────────────────────────
if(spsec_platform_lower STREQUAL "linux")
    add_executable(spsec_participant src/main_participant.c)
    target_link_libraries(spsec_participant spsec_core)
    target_compile_options(spsec_participant PRIVATE -Wsign-conversion -Wconversion)
    set(EXECUTABLE_OUTPUT_NAME "spsec_participant")
elseif(spsec_platform_lower STREQUAL "lpc55s16")
    # Baremetal entry point (to be provided by application)
    # add_executable(spsec_lpc55s16 platform/lpc55s16/main.c)
    # target_link_libraries(spsec_lpc55s16 spsec_core)
    message(STATUS "LPC55S16: Library-only build. Provide your own main.c linking spsec_core.")
    set(EXECUTABLE_OUTPUT_NAME "spsec_lpc55s16")
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Tests (Linux only)
# ─────────────────────────────────────────────────────────────────────────────
option(SPSEC_BUILD_TESTS "Build the SPsec unit/e2e test suite" ON)
if(spsec_platform_lower STREQUAL "linux" AND SPSEC_BUILD_TESTS)
    enable_testing()
    add_executable(test_crypto tests/test_crypto.c)
    target_link_libraries(test_crypto spsec_core)
    add_test(NAME crypto_kat COMMAND test_crypto)

    add_executable(test_auth_only tests/test_auth_only.c)
    target_link_libraries(test_auth_only spsec_core)
    add_test(NAME auth_only COMMAND test_auth_only)

    add_executable(test_nonce tests/test_nonce.c)
    target_link_libraries(test_nonce spsec_core)
    add_test(NAME nonce_construction COMMAND test_nonce)

    add_executable(test_timer tests/test_timer.c)
    target_link_libraries(test_timer spsec_core)
    add_test(NAME timer_guard COMMAND test_timer)

    add_executable(test_participant_state tests/test_participant_state.c)
    target_link_libraries(test_participant_state spsec_core)
    add_test(NAME participant_state_transitions COMMAND test_participant_state)

    add_executable(test_register_dispatch tests/test_register_dispatch.c)
    target_link_libraries(test_register_dispatch spsec_core)
    add_test(NAME register_dispatch COMMAND test_register_dispatch)

    add_executable(test_protocol_parsers tests/test_protocol_parsers.c)
    target_link_libraries(test_protocol_parsers spsec_core)
    add_test(NAME protocol_parsers COMMAND test_protocol_parsers)

    add_executable(test_config tests/test_config.c)
    target_link_libraries(test_config spsec_core)
    add_test(NAME config_validation COMMAND test_config)

    add_executable(test_keys tests/test_keys.c)
    target_link_libraries(test_keys spsec_core)
    add_test(NAME keys_lifecycle COMMAND test_keys)

    add_executable(test_register_validation tests/test_register_validation.c)
    target_link_libraries(test_register_validation spsec_core)
    add_test(NAME register_validation COMMAND test_register_validation)

    add_executable(test_messages tests/test_messages.c)
    target_link_libraries(test_messages spsec_core)
    add_test(NAME messages_lifecycle COMMAND test_messages)

    add_executable(test_session_timeout tests/test_session_timeout.c)
    target_link_libraries(test_session_timeout spsec_core)
    add_test(NAME session_timeout COMMAND test_session_timeout)

    add_executable(test_register_write_apply tests/test_register_write_apply.c)
    target_link_libraries(test_register_write_apply spsec_core)
    add_test(NAME register_write_apply COMMAND test_register_write_apply)

    add_executable(test_register_write_status tests/test_register_write_status.c)
    target_link_libraries(test_register_write_status spsec_core)
    add_test(NAME register_write_status COMMAND test_register_write_status)

    add_executable(test_register_write_code_update tests/test_register_write_code_update.c)
    target_link_libraries(test_register_write_code_update spsec_core)
    add_test(NAME register_write_code_update COMMAND test_register_write_code_update)

    add_executable(test_nvol_storage_binary tests/test_nvol_storage_binary.c)
    target_link_libraries(test_nvol_storage_binary spsec_core)
    add_test(NAME nvol_storage_binary COMMAND test_nvol_storage_binary)

    add_executable(test_participant_keys_ts tests/test_participant_keys_ts.c)
    target_link_libraries(test_participant_keys_ts spsec_core)
    add_test(NAME participant_keys_ts COMMAND test_participant_keys_ts)

    add_executable(test_comm_key_rederivation tests/test_comm_key_rederivation.c)
    target_link_libraries(test_comm_key_rederivation spsec_core)
    add_test(NAME comm_key_rederivation COMMAND test_comm_key_rederivation)

    add_executable(test_csalt_rederivation tests/test_csalt_rederivation.c)
    target_link_libraries(test_csalt_rederivation spsec_core)
    add_test(NAME csalt_rederivation COMMAND test_csalt_rederivation)

    add_executable(test_sync_broadcast_no_window tests/test_sync_broadcast_no_window.c)
    target_link_libraries(test_sync_broadcast_no_window spsec_core)
    add_test(NAME sync_broadcast_no_window COMMAND test_sync_broadcast_no_window)

    add_executable(test_appdata_aad tests/test_appdata_aad.c)
    target_link_libraries(test_appdata_aad spsec_core)
    add_test(NAME appdata_aad COMMAND test_appdata_aad)

    add_executable(test_tick_scaling tests/test_tick_scaling.c)
    target_link_libraries(test_tick_scaling spsec_core)
    add_test(NAME tick_scaling COMMAND test_tick_scaling)

    add_executable(test_sync_restart_recovery tests/test_sync_restart_recovery.c)
    target_link_libraries(test_sync_restart_recovery spsec_core)
    add_test(NAME sync_restart_recovery COMMAND test_sync_restart_recovery)

    add_executable(test_participant_stop_flag tests/test_participant_stop_flag.c)
    target_link_libraries(test_participant_stop_flag spsec_core)
    add_test(NAME participant_stop_flag COMMAND test_participant_stop_flag)

    add_executable(test_heartbeat_cycle tests/test_heartbeat_cycle.c)
    target_link_libraries(test_heartbeat_cycle spsec_core)
    add_test(NAME heartbeat_cycle COMMAND test_heartbeat_cycle)

    add_executable(test_participant_storage tests/test_participant_storage.c)
    target_link_libraries(test_participant_storage spsec_core)
    add_test(NAME participant_storage COMMAND test_participant_storage)

    add_executable(test_internal_events tests/test_internal_events.c)
    target_link_libraries(test_internal_events spsec_core)
    add_test(NAME internal_events COMMAND test_internal_events)

    add_executable(test_timesync_refresh tests/test_timesync_refresh.c)
    target_link_libraries(test_timesync_refresh spsec_core)
    add_test(NAME timesync_refresh COMMAND test_timesync_refresh)

    add_executable(test_warning_hold_time tests/test_warning_hold_time.c)
    target_link_libraries(test_warning_hold_time spsec_core)
    add_test(NAME warning_hold_time COMMAND test_warning_hold_time)

    add_executable(test_heartbeat_timeouts tests/test_heartbeat_timeouts.c)
    target_link_libraries(test_heartbeat_timeouts spsec_core)
    add_test(NAME heartbeat_timeouts COMMAND test_heartbeat_timeouts)

    add_executable(test_timesync_ready tests/test_timesync_ready.c)
    target_link_libraries(test_timesync_ready spsec_core)
    add_test(NAME timesync_ready COMMAND test_timesync_ready)

    add_executable(test_session_handshake tests/test_session_handshake.c)
    target_link_libraries(test_session_handshake spsec_core)
    add_test(NAME session_handshake COMMAND test_session_handshake)

    add_executable(test_register_read tests/test_register_read.c)
    target_link_libraries(test_register_read spsec_core)
    add_test(NAME register_read COMMAND test_register_read)

    add_executable(test_dll_events tests/test_dll_events.c)
    target_link_libraries(test_dll_events spsec_core)
    add_test(NAME dll_events COMMAND test_dll_events)

    add_executable(test_event_loops tests/test_event_loops.c)
    target_link_libraries(test_event_loops spsec_core)
    add_test(NAME event_loops COMMAND test_event_loops)

    add_executable(test_can_link_recovery tests/test_can_link_recovery.c)
    target_link_libraries(test_can_link_recovery spsec_core)
    add_test(NAME can_link_recovery COMMAND test_can_link_recovery)

    find_program(TSHARK_BIN tshark)
    if(TSHARK_BIN)
        add_test(NAME wireshark_dissector COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_wireshark_dissector_test.sh)
        set_tests_properties(wireshark_dissector PROPERTIES ENVIRONMENT "SPSEC_DISSECTOR=${CMAKE_CURRENT_SOURCE_DIR}/wireshark/spsec.lua" TIMEOUT 30)
    endif()

    # E2E Sync-role restart recovery; needs live vcan and the default salt build
    if(SPSEC_SALT_LEN STREQUAL "8")
        execute_process(COMMAND ip link show vcan0
                        RESULT_VARIABLE VCAN0_MISSING
                        OUTPUT_QUIET ERROR_QUIET)
        if(VCAN0_MISSING EQUAL 0)
            add_test(NAME e2e_sync_restart_recovery
                    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_e2e_sync_restart.sh)
            set_tests_properties(e2e_sync_restart_recovery PROPERTIES
                                 ENVIRONMENT "SPSEC_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                                 TIMEOUT 90)
        endif()
    endif()

    add_executable(test_fallback_decryption tests/test_fallback_decryption.c)
    target_link_libraries(test_fallback_decryption spsec_core)
    add_test(NAME fallback_decryption COMMAND test_fallback_decryption)

    add_executable(test_timer_dynamic_scale tests/test_timer_dynamic_scale.c)
    target_link_libraries(test_timer_dynamic_scale spsec_core)
    add_test(NAME timer_dynamic_scale COMMAND test_timer_dynamic_scale)

    add_executable(test_key_write_ordering tests/test_key_write_ordering.c)
    target_link_libraries(test_key_write_ordering spsec_core)
    add_test(NAME key_write_ordering COMMAND test_key_write_ordering)

    add_executable(test_code_update_abort tests/test_code_update_abort.c)
    target_link_libraries(test_code_update_abort spsec_core)
    add_test(NAME code_update_abort COMMAND test_code_update_abort)

    add_executable(test_nvol_corruption tests/test_nvol_corruption.c)
    target_link_libraries(test_nvol_corruption spsec_core)
    add_test(NAME nvol_corruption COMMAND test_nvol_corruption)

    add_executable(test_timesync_auth tests/test_timesync_auth.c)
    target_link_libraries(test_timesync_auth spsec_core)
    add_test(NAME timesync_auth COMMAND test_timesync_auth)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Static analysis targets (Linux only)
# ─────────────────────────────────────────────────────────────────────────────
if(spsec_platform_lower STREQUAL "linux")
    find_program(CPPCHECK cppcheck)
    if(CPPCHECK)
        add_custom_target(cppcheck
            COMMAND ${CPPCHECK} --enable=all
                    --suppress=missingIncludeSystem
                    --suppress=unusedFunction
                    --force
                    --xml --xml-version=2
                    --output-file=${CMAKE_BINARY_DIR}/cppcheck-report.xml
                    ${CMAKE_SOURCE_DIR}/spsec_participant
                    ${CMAKE_SOURCE_DIR}/common
                    ${CMAKE_SOURCE_DIR}/platform
                    ${CMAKE_SOURCE_DIR}/src
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Running cppcheck static analysis"
        )
        message(STATUS "cppcheck: Found - 'cppcheck' target available")
    else()
        message(STATUS "cppcheck: Not found - install to enable static analysis")
    endif()

    find_program(CLANG_TIDY clang-tidy)
    if(CLANG_TIDY AND EXISTS ${CMAKE_BINARY_DIR}/compile_commands.json)
        # Run clang-tidy only on sources compiled for the active crypto backend
        set(CLANG_TIDY_COMMON_FILES_REL ${COMMON_SOURCES} ${SPSEC_BACKEND_SOURCES})
        list(REMOVE_DUPLICATES CLANG_TIDY_COMMON_FILES_REL)
        set(CLANG_TIDY_COMMON_FILES "")
        foreach(_ctf ${CLANG_TIDY_COMMON_FILES_REL})
            list(APPEND CLANG_TIDY_COMMON_FILES ${CMAKE_SOURCE_DIR}/${_ctf})
        endforeach()

        add_custom_target(clang-tidy
            COMMAND ${CLANG_TIDY} -p ${CMAKE_BINARY_DIR}
                    -checks=-*,clang-analyzer-*,cert-*,misc-*,readability-*
                    # Silence GCC-specific options when parsed by Clang
                    --extra-arg=-Wno-unknown-warning-option
                    ${CMAKE_SOURCE_DIR}/spsec_participant/*.c
                    ${CLANG_TIDY_COMMON_FILES}
                    ${CMAKE_SOURCE_DIR}/platform/*.c
                    ${CMAKE_SOURCE_DIR}/src/*.c
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Running clang-tidy static analysis"
        )
        message(STATUS "clang-tidy: Found - 'clang-tidy' target available")
    else()
        message(STATUS "clang-tidy: Not found or compile_commands.json missing")
    endif()
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Documentation (Doxygen)
# ─────────────────────────────────────────────────────────────────────────────
option(BUILD_DOCS "Build API documentation with Doxygen" OFF)
if(BUILD_DOCS)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/docs)
        set(DOXYGEN_RECURSIVE YES)
        set(DOXYGEN_EXTRACT_ALL YES)
        doxygen_add_docs(doc
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/common
            ${CMAKE_SOURCE_DIR}/platform
            ${CMAKE_SOURCE_DIR}/spsec_participant
            ${CMAKE_SOURCE_DIR}/spsec_can_protocol
            COMMENT "Generating API documentation with Doxygen"
        )
        message(STATUS "Doxygen: Found - 'doc' target available")
    else()
        message(WARNING "Doxygen not found - documentation target disabled")
    endif()
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Installation & Packaging
# ─────────────────────────────────────────────────────────────────────────────
if(spsec_platform_lower STREQUAL "linux")
    # Install library
    install(TARGETS spsec_core
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
    )

    # Install headers
    install(DIRECTORY common/hal/include/
        DESTINATION include/spsec/hal
        FILES_MATCHING PATTERN "*.h"
    )
    install(DIRECTORY common/include/
        DESTINATION include/spsec/common
        FILES_MATCHING PATTERN "*.h"
    )
    install(DIRECTORY spsec_participant/include/
        DESTINATION include/spsec/participant
        FILES_MATCHING PATTERN "*.h"
    )
    install(DIRECTORY spsec_can_protocol/include/
        DESTINATION include/spsec/protocol
        FILES_MATCHING PATTERN "*.h"
    )

    # Install executable
    install(TARGETS spsec_participant
        RUNTIME DESTINATION bin
    )

    # CPack configuration
    include(CPack)
    set(CPACK_PACKAGE_NAME "spsec-participant")
    set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "CANopenS SPsec Participant")
    set(CPACK_PACKAGE_VENDOR "Hochschule Offenburg - ivESK")
    set(CPACK_PACKAGE_CONTACT "ivESK")
    set(CPACK_GENERATOR "TGZ;DEB")
endif()
