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
	src/h_export.cpp
	src/meta_api.cpp
	src/dllapi.cpp
	src/qproto_metamod_compat.cpp
	src/qproto_hook.cpp
	src/qproto_log.cpp
	src/qproto_cfg.cpp
	src/qproto_authorizers.cpp
	src/qproto_utils.cpp
	src/Rijndael.cpp
	src/sha2.cpp
	${DEP_METAMOD}/sdk_util.cpp
)

target_include_directories(qproto PRIVATE
	src
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
# Self-tests - no engine dependency for the first three (pure logic against known
# test vectors / a synthetic ticket), so they build and run anywhere.
# ============================================================================

if(QPROTO_BUILD_TESTS)
	enable_testing()

	function(qproto_add_test name)
		add_executable(${name} src/${name}.cpp ${ARGN})
		target_include_directories(${name} PRIVATE src)
		target_compile_options(${name} PRIVATE ${QPROTO_M32_FLAGS})
		target_link_options(${name} PRIVATE ${QPROTO_M32_FLAGS})
		add_test(NAME ${name} COMMAND ${name})
	endfunction()

	# qproto_cfg_stub.cpp provides g_qprotoConfig (defaults: everything on) without
	# pulling in the real Qproto_Cfg_Load()'s g_engfuncs dependency - these tests call
	# the authorizer functions directly and never touch config file loading itself.
	qproto_add_test(crypto_selftest src/Rijndael.cpp src/sha2.cpp)
	qproto_add_test(authorizers_selftest src/qproto_authorizers.cpp src/qproto_cfg_stub.cpp src/qproto_utils.cpp src/Rijndael.cpp src/sha2.cpp)
	qproto_add_test(oldrevemu_selftest src/qproto_authorizers.cpp src/qproto_cfg_stub.cpp src/qproto_utils.cpp src/Rijndael.cpp src/sha2.cpp)

	# Exercises the actual mprotect+JMP detour mechanism against a real engine_i486.so
	# via dlopen - never calls through the patched function (see the file's own header
	# comment for why), just proves install/restore is byte-exact. Needs a real engine
	# binary, so it's opt-in via QPROTO_TEST_ENGINE_PATH rather than always-on.
	add_executable(hook_patch_selftest src/hook_patch_selftest.cpp)
	target_compile_options(hook_patch_selftest PRIVATE ${QPROTO_M32_FLAGS})
	target_link_options(hook_patch_selftest PRIVATE ${QPROTO_M32_FLAGS})
	target_link_libraries(hook_patch_selftest PRIVATE dl)

	if(QPROTO_TEST_ENGINE_PATH)
		get_filename_component(QPROTO_TEST_ENGINE_DIR "${QPROTO_TEST_ENGINE_PATH}" DIRECTORY)
		add_test(NAME hook_patch_selftest COMMAND hook_patch_selftest "${QPROTO_TEST_ENGINE_PATH}")
		# engine_i486.so needs its sibling libs (libsteam_api.so etc.) on the loader
		# path - same reason the real server's hlds_run script prepends "." to
		# LD_LIBRARY_PATH before starting hlds_linux.
		set_tests_properties(hook_patch_selftest PROPERTIES
			ENVIRONMENT "LD_LIBRARY_PATH=${QPROTO_TEST_ENGINE_DIR}:$ENV{LD_LIBRARY_PATH}"
		)
	endif()
endif()
