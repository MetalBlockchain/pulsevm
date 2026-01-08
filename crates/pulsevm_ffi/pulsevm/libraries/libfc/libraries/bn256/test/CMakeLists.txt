function(add_test_executable TARGET )
  add_executable (${TARGET} ${ARGN})
  target_include_directories(${TARGET} PRIVATE ${Boost_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/../src)
  target_link_libraries (${TARGET} PRIVATE bn256 Catch2::Catch2WithMain)
  add_test(
    NAME ${TARGET}
    COMMAND ${TARGET}
  )
endfunction()

add_test_executable(gfp_test gfp_test.cpp)
add_test_executable(bn256_test bn256_test.cpp)
add_test_executable(lattice_test lattice_test.cpp)
add_test_executable(example_test example_test.cpp)
add_test_executable(main_test main_test.cpp)

add_executable (bn256_benchmark bn256_benchmark.cpp)
target_link_libraries(bn256_benchmark bn256)
