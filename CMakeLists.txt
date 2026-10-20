cmake_minimum_required(VERSION 3.16)
project(qproto C CXX)

# Authum client module (ABI 0.2). Metamod plugin build lives on branch 1.0.0 only.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

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

set(METAMOD_P_DIR "${CMAKE_SOURCE_DIR}/lib/metamod-p")
if (NOT EXISTS "${METAMOD_P_DIR}/metamod/meta_api.h")
    message(FATAL_ERROR "lib/metamod-p missing — clone Bots-United/metamod-p into lib/metamod-p")
endif ()
set(DEP_METAMOD "${METAMOD_P_DIR}/metamod")
set(DEP_HLSDK "${METAMOD_P_DIR}/hlsdk")

add_library(qproto MODULE
        src/authum/info.c
        src/authum/module.c
        src/authum/bridge.cpp
        src/authum/host_log.cpp
        src/authum/host_crypto.cpp
        src/authum/data_dir.cpp
        src/authum/engfuncs_shim.cpp
        src/qproto/qproto_hook.cpp
        src/qproto/qproto_engine.cpp
        src/qproto/qproto_cfg.cpp
        src/qproto/qproto_authorizers.cpp
        src/qproto/qproto_utils.cpp
        src/qproto/qproto_bans.cpp
        src/qproto/qproto_client_state.cpp
        src/qproto/qproto_api.cpp
        src/qproto/qproto_log.cpp
        src/qproto/qproto_paths.cpp
        "${DEP_METAMOD}/sdk_util.cpp"
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
        "${DEP_METAMOD}"
        "${DEP_HLSDK}/dlls"
        "${DEP_HLSDK}/engine"
        "${DEP_HLSDK}/common"
        "${DEP_HLSDK}/pm_shared"
)

target_compile_definitions(qproto PRIVATE linux LINUX)

if (NOT MSVC)
    target_compile_options(qproto PRIVATE
            -m32
            -fpermissive
            -fvisibility=hidden
            -Wall
            -ffunction-sections
            -fdata-sections
    )
    target_link_options(qproto PRIVATE
            -m32
            -static-libgcc
            -static-libstdc++
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
