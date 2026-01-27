file(GLOB HEADERS "include/pulsevm/chain/*.hpp" )

## SORT .cpp by most likely to change / break compile
add_library( pulsevm_chain
   name.cpp
   genesis_state_root_key.cpp
   genesis_state.cpp
   authority.cpp
   pulse_contract_abi_bin.cpp
   ${HEADERS}
)

target_link_libraries( pulsevm_chain PUBLIC bn256 fc chainbase
   Boost::signals2 Boost::hana Boost::property_tree Boost::multi_index Boost::asio Boost::lockfree
   Boost::assign Boost::accumulators
)

target_include_directories( pulsevm_chain PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_BINARY_DIR}/include" )

install( TARGETS pulsevm_chain
   RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR}
   LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}
   ARCHIVE DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}
)
