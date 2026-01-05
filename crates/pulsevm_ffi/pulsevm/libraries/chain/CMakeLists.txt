file(GLOB HEADERS "include/pulsevm/*.hpp" )

# SORT .cpp by most likely to change / break compile
add_library( chain
    block_log.cpp
    name.cpp
    ${HEADERS}
)

target_link_libraries( chain PUBLIC bn256 fc chainbase softfloat
    Boost::signals2 Boost::hana Boost::property_tree Boost::multi_index Boost::asio Boost::lockfree
    Boost::assign Boost::accumulators Boost::rational
)

target_include_directories( chain PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_BINARY_DIR}/include" )