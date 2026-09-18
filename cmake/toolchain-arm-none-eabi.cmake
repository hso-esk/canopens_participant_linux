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

# ARM Cortex-M33 (LPC55S16) toolchain for bare metal

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR cortex-m33)

# Cross compiler
set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-common -fmessage-length=0")

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -specs=nano.specs -specs=nosys.specs")

# Find program utilities
set(CMAKE_OBJCOPY arm-none-eabi-objcopy)
set(CMAKE_OBJDUMP arm-none-eabi-objdump)
set(CMAKE_SIZE arm-none-eabi-size)

# MCUXpresso SDK path
if(NOT MCUX_SDK_PATH)
    message(FATAL_ERROR "MCUX_SDK_PATH not set. Set it to the MCUXpresso SDK root (e.g. $ENV{HOME}/mcuxpresso-sdk)")
endif()

message(STATUS "Using MCUXpresso SDK: ${MCUX_SDK_PATH}")

# Include SDK paths
include_directories(
    ${MCUX_SDK_PATH}/devices/LPC55S16
    ${MCUX_SDK_PATH}/devices/LPC55S16/drivers
    ${MCUX_SDK_PATH}/CMSIS/Include
    ${MCUX_SDK_PATH}/middleware/wolfssl
)

# Linker script (provided by SDK)
set(LINKER_SCRIPT ${MCUX_SDK_PATH}/devices/LPC55S16/gcc/MIMXRT555S_cm33.ld)
if(NOT EXISTS ${LINKER_SCRIPT})
    message(WARNING "Linker script not found at ${LINKER_SCRIPT}")
endif()

# Startup file (provided by SDK)
set(STARTUP_FILE ${MCUX_SDK_PATH}/devices/LPC55S16/gcc/startup_MIMXRT555S.S)
if(NOT EXISTS ${STARTUP_FILE})
    message(WARNING "Startup file not found at ${STARTUP_FILE}")
endif()

# FPU settings for Cortex-M33
set(FPU_FLAGS "-mfpu=fpv5-sp-d16 -mfloat-abi=hard")

# Debug/Release flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g3 -gdwarf-4")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g")
endif()