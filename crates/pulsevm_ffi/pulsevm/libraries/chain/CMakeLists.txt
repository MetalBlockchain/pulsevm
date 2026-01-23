file(GLOB HEADERS "include/pulsevm/chain/*.hpp" )

if((APPLE AND UNIX) OR (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD"))
   set(PLATFORM_TIMER_IMPL platform_timer_kqueue.cpp)
else()
   try_run(POSIX_TIMER_TEST_RUN_RESULT POSIX_TIMER_TEST_COMPILE_RESULT ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/platform_timer_posix_test.c)
   if(POSIX_TIMER_TEST_RUN_RESULT EQUAL 0)
      set(PLATFORM_TIMER_IMPL platform_timer_posix.cpp)
      set(CHAIN_RT_LINKAGE rt)
   else()
      set(PLATFORM_TIMER_IMPL platform_timer_asio_fallback.cpp)
   endif()
endif()

add_library( pulsevm_chain
    authority.cpp
    block_header.cpp
    chain_id_type.cpp
    chain_config.cpp
    genesis_state_root_key.cpp
    name.cpp
    ${HEADERS}
)

target_link_libraries( pulsevm_chain PUBLIC bn256 fc chainbase rt softfloat
    Boost::signals2 Boost::hana Boost::property_tree Boost::multi_index Boost::asio Boost::lockfree
    Boost::assign Boost::accumulators
)

target_include_directories( pulsevm_chain PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_BINARY_DIR}/include" )

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/pulsevm DESTINATION ${CMAKE_INSTALL_FULL_INCLUDEDIR} ${INSTALL_COMPONENT_ARGS})

install(TARGETS pulsevm_chain
   LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR} ${INSTALL_COMPONENT_ARGS}
   ARCHIVE DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR} ${INSTALL_COMPONENT_ARGS})

add_library(pulsevm_chain_wrap INTERFACE )
target_link_libraries(pulsevm_chain_wrap INTERFACE pulsevm_chain)