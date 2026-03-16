file(GLOB HEADERS "include/pulsevm/state_history/*.hpp")

add_library( state_history
  abi.cpp
  compression.cpp
  create_deltas.cpp
  ${HEADERS}
)

target_link_libraries( state_history PUBLIC pulsevm_chain fc chainbase )

target_include_directories( state_history PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )

install(TARGETS state_history
        LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})