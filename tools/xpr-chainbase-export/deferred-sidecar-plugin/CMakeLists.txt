file(GLOB HEADERS "include/eosio/deferred_transaction_sidecar_plugin/*.hpp")

add_library(deferred_transaction_sidecar_plugin
            deferred_transaction_sidecar_plugin.cpp
            ${HEADERS})

target_link_libraries(deferred_transaction_sidecar_plugin chain_plugin eosio_chain appbase)
target_include_directories(deferred_transaction_sidecar_plugin
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
