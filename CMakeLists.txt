cmake_minimum_required(VERSION 3.16)
project(qproto CXX)

# Metamod plugin build removed. Runtime module lives in Authum:
#   https://github.com/darwin128k/rapad-authum  (src/modules/qproto)
#
# This tree keeps sample config, license, and historical docs.
# Optional self-tests were Metamod/HLSDK-coupled; enable AUTHUM checkout to build
# the shipping .so instead.

message(STATUS "raspad-qproto: Metamod plugin target removed.")
message(STATUS "  Build qproto.so via Authum: cmake --build <authum-build> --target qproto_authum")

option(QPROTO_BUILD_TESTS "Legacy self-tests (disabled; sources moved to Authum)" OFF)
if (QPROTO_BUILD_TESTS)
    message(WARNING "QPROTO_BUILD_TESTS=ON but core sources moved to Authum — tests not configured")
endif ()
