# qproto tests: engine-free logic (qproto_core) against fake Authum ops.

add_executable(qproto_test_client client.c)
target_link_libraries(qproto_test_client PRIVATE qproto_core authum_client)
if (NOT MSVC)
    target_compile_options(qproto_test_client PRIVATE -m32 -Wall)
    target_link_options(qproto_test_client PRIVATE -m32)
endif ()
add_test(NAME qproto_client COMMAND qproto_test_client)

add_executable(qproto_test_vellum vellum.c)
target_link_libraries(qproto_test_vellum PRIVATE qproto_core authum_client)
if (NOT MSVC)
    target_compile_options(qproto_test_vellum PRIVATE -m32 -Wall)
    target_link_options(qproto_test_vellum PRIVATE -m32)
endif ()
add_test(NAME qproto_vellum COMMAND qproto_test_vellum)
