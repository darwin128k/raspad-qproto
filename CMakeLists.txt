cmake_minimum_required(VERSION 3.16)
project(qproto C)

# Authum client module (ABI 0.2), pure C11. Metamod plugin build lives on branch 1.0.0 only.
# No HLSDK / metamod-p here — engine + crypto go through Authum host facades.

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

set(AUTHUM_SRC_DIR "" CACHE PATH "Checkout of raspad-authum (for include/authum)")
if (AUTHUM_SRC_DIR STREQUAL "" OR NOT EXISTS "${AUTHUM_SRC_DIR}/include/authum/client.h")
    foreach (_cand IN ITEMS
            "${CMAKE_SOURCE_DIR}/../raspad-authum"
            "H:/Projects/raspad-authum"
            "/mnt/h/Projects/raspad-authum")
        if (EXISTS "${_cand}/include/authum/client.h")
            set(AUTHUM_SRC_DIR "${_cand}" CACHE PATH "Checkout of raspad-authum" FORCE)
            break()
        endif ()
    endforeach ()
endif ()
if (NOT EXISTS "${AUTHUM_SRC_DIR}/include/authum/client.h")
    message(FATAL_ERROR "AUTHUM_SRC_DIR not found (need include/authum/client.h)")
endif ()
message(STATUS "qproto: Authum headers from ${AUTHUM_SRC_DIR}")

add_library(qproto MODULE
        src/authum/info.c
        src/authum/module.c
        src/authum/bridge.c
        src/authum/data_dir.c
        src/qproto/qproto_hook.c
        src/qproto/qproto_engine.c
        src/qproto/qproto_cfg.c
        src/qproto/qproto_authorizers.c
        src/qproto/qproto_utils.c
        src/qproto/qproto_bans.c
        src/qproto/qproto_client_state.c
        src/qproto/qproto_api.c
        src/qproto/qproto_logger.c
        src/qproto/qproto_paths.c
)

set_target_properties(qproto PROPERTIES
        PREFIX ""
        OUTPUT_NAME "qproto"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules/qproto"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/modules/qproto"
)

target_include_directories(qproto PRIVATE
        "${AUTHUM_SRC_DIR}/include"
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_SOURCE_DIR}/src/authum"
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

target_link_libraries(qproto PRIVATE dl m)

if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    if (CMAKE_STRIP)
        add_custom_command(TARGET qproto POST_BUILD
                COMMAND ${CMAKE_STRIP} --strip-unneeded "$<TARGET_FILE:qproto>"
                COMMENT "strip qproto.so")
    endif ()
endif ()
