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

# CMake toolchain file for cross-compiling spsec_core to the LPC55S16
# (Cortex-M33, no FPU on this part). Used by both the lpc55s16-* CMake
# presets and tests/run_cross_compile_lpc55s16.sh.
#
# This is a library-only cross-compile: no application main.c, no linker
# script, no SDK is required to build spsec_core as a static library.
# A real firmware image additionally needs the MCUXpresso SDK startup
# code / linker script and MCUX_SDK_PATH set (see CMakeLists.txt).

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Building a static library for a freestanding target: skip the linker
# check CMake normally does while probing the compiler, since there is
# no libc/startup code available yet.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

find_program(ARM_NONE_EABI_GCC arm-none-eabi-gcc)
if(NOT ARM_NONE_EABI_GCC)
    message(FATAL_ERROR
        "arm-none-eabi-gcc not found. Install with: "
        "sudo apt install gcc-arm-none-eabi binutils-arm-none-eabi")
endif()

set(CMAKE_C_COMPILER ${ARM_NONE_EABI_GCC})
set(CMAKE_ASM_COMPILER ${ARM_NONE_EABI_GCC})

# LPC55S16: Cortex-M33, no hardware FPU on this part.
set(CPU_FLAGS "-mcpu=cortex-m33 -mthumb -mfloat-abi=soft")
set(CMAKE_C_FLAGS_INIT "${CPU_FLAGS}")
set(CMAKE_ASM_FLAGS_INIT "${CPU_FLAGS}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
