# Self-tests for qproto. The first three are pure logic (known test vectors / a
# synthetic ticket) - no engine dependency, build and run anywhere. The fourth
# exercises the real mprotect+JMP detour mechanism against an actual engine_i486.so.
#
# Shared plugin sources (Rijndael, sha2, qproto_authorizers, qproto_utils) are
# reused straight from ../src/qproto rather than duplicated here.

set(QPROTO_SRC ${CMAKE_SOURCE_DIR}/src/qproto)

function(qproto_add_test name)
	add_executable(${name} src/qproto/${name}.cpp ${ARGN})
	target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
	target_compile_options(${name} PRIVATE ${QPROTO_M32_FLAGS})
	target_link_options(${name} PRIVATE ${QPROTO_M32_FLAGS})
	add_test(NAME ${name} COMMAND ${name})
endfunction()

# src/qproto/qproto_cfg_stub.cpp (here, not in the main plugin) provides g_qprotoConfig
# (defaults: everything on) without pulling in the real Qproto_Cfg_Load()'s
# g_engfuncs dependency - these tests call the authorizer functions directly and
# never touch config file loading itself.
qproto_add_test(crypto_selftest ${QPROTO_SRC}/Rijndael.cpp ${QPROTO_SRC}/sha2.cpp)
qproto_add_test(authorizers_selftest ${QPROTO_SRC}/qproto_authorizers.cpp src/qproto/qproto_cfg_stub.cpp ${QPROTO_SRC}/qproto_utils.cpp ${QPROTO_SRC}/Rijndael.cpp ${QPROTO_SRC}/sha2.cpp)
qproto_add_test(oldrevemu_selftest ${QPROTO_SRC}/qproto_authorizers.cpp src/qproto/qproto_cfg_stub.cpp ${QPROTO_SRC}/qproto_utils.cpp ${QPROTO_SRC}/Rijndael.cpp ${QPROTO_SRC}/sha2.cpp)

# Exercises the actual mprotect+JMP detour mechanism against a real engine_i486.so
# via dlopen - never calls through the patched function (see the file's own header
# comment for why), just proves install/restore is byte-exact. Needs a real engine
# binary, so it's opt-in via QPROTO_TEST_ENGINE_PATH rather than always-on.
add_executable(hook_patch_selftest src/qproto/hook_patch_selftest.cpp)
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
