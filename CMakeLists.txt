cmake_minimum_required(VERSION 3.16)
project(qproto C)

# Authum client module (ABI 1.0), pure C11. Metamod plugin build lives on branch 1.0.0 only.
# No HLSDK / metamod-p here — engine + crypto go through Authum host facades.

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Point at another Authum checkout to build against unreleased Authum changes:
#   cmake -S . -B build -DAUTHUM_DIR=/path/to/raspad-authum
set(AUTHUM_DIR "${CMAKE_SOURCE_DIR}/lib/authum" CACHE PATH "Authum source tree")
if (NOT EXISTS "${AUTHUM_DIR}/client/CMakeLists.txt")
    message(FATAL_ERROR
            "lib/authum missing — run: git submodule update --init --recursive lib/authum")
endif ()

add_subdirectory("${AUTHUM_DIR}/client" authum_client)

# Engine-independent logic, shared by the module and the tests.
add_library(qproto_core STATIC
        src/qproto/client/auth/kind.c
        src/qproto/client/state.c
        src/qproto/client/long_authid.c
        src/qproto/command.c
        src/qproto/authorizers.c
        src/qproto/utils.c
        src/qproto/vellum/address.c
        src/qproto/vellum/keystore.c
)
target_include_directories(qproto_core PUBLIC "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(qproto_core PUBLIC authum_client)
set_target_properties(qproto_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
if (NOT MSVC)
    target_compile_options(qproto_core PRIVATE -m32 -fvisibility=hidden -Wall
            -ffunction-sections -fdata-sections)
endif ()

add_library(qproto MODULE
        src/authum/info.c
        src/authum/module.c
        src/authum/bridge.c
        src/qproto/hook.c
        src/qproto/engine.c
        src/qproto/config.c
        src/qproto/events.c
        src/qproto/logger.c
)

set_target_properties(qproto PROPERTIES
        PREFIX ""
        OUTPUT_NAME "qproto"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules/qproto"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules/qproto"
)

target_include_directories(qproto PRIVATE
        "${CMAKE_SOURCE_DIR}/include"
)

target_compile_definitions(qproto PRIVATE linux LINUX)

if (NOT MSVC)
    target_compile_options(qproto PRIVATE
            -m32
            -fvisibility=hidden
            -Wall
            -ffunction-sections
            -fdata-sections
    )
    target_link_options(qproto PRIVATE
            -m32
            -static-libgcc
            "LINKER:--gc-sections"
    )
endif ()

target_link_libraries(qproto PRIVATE qproto_core authum_client dl m)

option(QPROTO_BUILD_TESTS "Build qproto tests (ctest)" ON)
if (QPROTO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()

if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    if (CMAKE_STRIP)
        add_custom_command(TARGET qproto POST_BUILD
                COMMAND ${CMAKE_STRIP} --strip-unneeded "$<TARGET_FILE:qproto>"
                COMMENT "strip qproto.so")
    endif ()
endif ()
