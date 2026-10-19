cmake_minimum_required(VERSION 3.16)
project(qproto CXX)

# qproto is a Metamod-P plugin for a 32-bit (i386) HLDS engine build - everything
# here is built 32-bit regardless of host word size, hence -m32 on every target's
# compile and link step below.
#
# gnu++17 (not plain c++17): lib/metamod-p/metamod/osdep.h keys off the GNU `linux`
# macro, which strict ISO modes (-std=c++17) suppress and which is required to avoid
# an `#error "OS unrecognized"` - see qproto_hook.cpp's header comment for the story.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

option(QPROTO_BUILD_TESTS "Build the standalone self-tests (crypto, authorizers, hook mechanism)" ON)

# Path to a real engine_i486.so to run hook_patch_selftest against (optional - that
# test is skipped from `ctest` if this isn't set). Never ship/commit an actual copy
# of the engine binary; point this at wherever your server checkout lives, e.g.:
#   cmake -B build -DQPROTO_TEST_ENGINE_PATH=/path/to/server/engine_i486.so
set(QPROTO_TEST_ENGINE_PATH "" CACHE FILEPATH "Path to engine_i486.so for hook_patch_selftest")

# lib/metamod-p is the Bots-United/metamod-p submodule, pinned to tag v1.21p37 (the
# exact Metamod build installed on the server) - its own hlsdk/ subdirectory carries
# the matching HLSDK headers, so there's no separate HLSDK dependency to track.
set(METAMOD_P_DIR ${CMAKE_SOURCE_DIR}/lib/metamod-p)
set(DEP_METAMOD ${METAMOD_P_DIR}/metamod)
set(DEP_HLSDK   ${METAMOD_P_DIR}/hlsdk)
set(QPROTO_M32_FLAGS -m32)

if(NOT EXISTS ${DEP_METAMOD}/meta_api.h)
	message(FATAL_ERROR "lib/metamod-p submodule is missing/empty - run: git submodule update --init --recursive")
endif()

# ============================================================================
# Main plugin: cstrike/addons/qproto/qproto_i386.so
# ============================================================================

add_library(qproto SHARED
	src/qproto/h_export.cpp
	src/qproto/meta_api.cpp
	src/qproto/dllapi.cpp
	src/qproto/qproto_metamod_compat.cpp
	src/qproto/qproto_hook.cpp
	src/qproto/qproto_engine.cpp
	src/qproto/qproto_log.cpp
	src/qproto/qproto_cfg.cpp
	src/qproto/qproto_authorizers.cpp
	src/qproto/qproto_utils.cpp
	src/qproto/qproto_bans.cpp
	src/qproto/qproto_client_state.cpp
	src/qproto/qproto_api.cpp
	src/qproto/Rijndael.cpp
	src/qproto/sha2.cpp
	${DEP_METAMOD}/sdk_util.cpp
)

# "include" (not "include/qproto") - our own code says #include "qproto/foo.h", so
# the qproto/ path segment must come from the directory name, not the include root.
target_include_directories(qproto PRIVATE
	include
	${DEP_METAMOD}
	${DEP_HLSDK}/dlls
	${DEP_HLSDK}/engine
	${DEP_HLSDK}/common
	${DEP_HLSDK}/pm_shared
)

# -fpermissive: the vendored HLSDK/Metamod-P headers predate strict C++17 (implicit
# int, old-style casts flagged as errors otherwise, etc.) - same as every other
# HLSDK-based mod's build.
target_compile_options(qproto PRIVATE ${QPROTO_M32_FLAGS} -fpermissive -Wall)

# -static-libgcc/-static-libstdc++: the server's own bundled (ancient) libstdc++.so.6
# sits earlier in LD_LIBRARY_PATH than the system one and lacks the CXXABI symbols a
# modern compiler emits, which makes Metamod's dlopen() of the plugin fail *silently*
# (no console error at all - see the qproto.log debugging session that found this).
# Statically linking sidesteps needing the host's C++ runtime version at all.
target_link_options(qproto PRIVATE ${QPROTO_M32_FLAGS} -static-libgcc -static-libstdc++)
target_link_libraries(qproto PRIVATE dl)

set_target_properties(qproto PROPERTIES
	PREFIX ""
	OUTPUT_NAME "qproto_i386"
	SUFFIX ".so"
	POSITION_INDEPENDENT_CODE ON
)

# ============================================================================
# Self-tests - see tests/CMakeLists.txt
# ============================================================================

if(QPROTO_BUILD_TESTS)
	enable_testing()
	add_subdirectory(tests)
endif()
