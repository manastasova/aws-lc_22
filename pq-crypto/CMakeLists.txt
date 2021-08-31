#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

cmake_minimum_required (VERSION 2.8.12)

include_directories(../include)
include_directories(../crypto)

# get all header and source files
file(GLOB PQ_HEADERS "*.h" "sike_r3/*.h")
file(GLOB PQ_SRC "*.c" "sike_r3/*.c")

# compile
add_library(pq_lib ${PQ_HEADERS} ${PQ_SRC})



# Doesn't work bc of following...
# Practice using GoogleTest try 2
if(BUILD_TESTING)
    #add_subdirectory(test)

    add_executable(
        hello_test

        hello_test.cc
        $<TARGET_OBJECTS:boringssl_gtest_main>
    )
    add_dependencies(hello_test global_target)
    target_link_libraries(hello_test test_support_lib boringssl_gtest pq-crypto)
endif()

include(GoogleTest)
gtest_discover_tests(hello_test)

install(TARGETS pq-crypto
        EXPORT pq-crypto-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

configure_file("cmake/pq-crypto-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/pq-crypto-config.cmake"
        @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/pq-crypto-config.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pq-crypto/cmake"
        COMPONENT Development)
