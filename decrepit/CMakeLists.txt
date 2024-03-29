include_directories(../include)

add_library(
  decrepit

  bio/base64_bio.c
  blowfish/blowfish.c
  cast/cast.c
  cast/cast_tables.c
  cfb/cfb.c
  des/cfb64ede.c
  dh/dh_decrepit.c
  dsa/dsa_decrepit.c
  evp/dss1.c
  evp/evp_do_all.c
  obj/obj_decrepit.c
  rc4/rc4_decrepit.c
  ripemd/ripemd.c
  rsa/rsa_decrepit.c
  ssl/ssl_decrepit.c
  x509/x509_decrepit.c
)
target_compile_definitions(decrepit PRIVATE BORINGSSL_IMPLEMENTATION)

add_dependencies(decrepit global_target)

target_link_libraries(decrepit crypto ssl)

if(BUILD_TESTING)
  add_executable(
    ${DECREPIT_TEST_EXEC}

    blowfish/blowfish_test.cc
    cast/cast_test.cc
    cfb/cfb_test.cc
    evp/evp_test.cc
    ripemd/ripemd_test.cc

    $<TARGET_OBJECTS:boringssl_gtest_main>
  )

  add_dependencies(${DECREPIT_TEST_EXEC} global_target)

  target_link_libraries(${DECREPIT_TEST_EXEC} test_support_lib boringssl_gtest decrepit
                        crypto)
  if(WIN32)
    target_link_libraries(${DECREPIT_TEST_EXEC} ws2_32)
  endif()
  add_dependencies(all_tests ${DECREPIT_TEST_EXEC})
endif()

install(TARGETS decrepit
        EXPORT decrepit-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
