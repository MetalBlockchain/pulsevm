set(APPBASE_INSTALL_COMPONENT "dev")
set(SOFTFLOAT_INSTALL_COMPONENT "dev")
set(EOSVM_INSTALL_COMPONENT "dev")
set(BN256_INSTALL_COMPONENT "dev")

set( Boost_USE_MULTITHREADED      ON )
set( Boost_USE_STATIC_LIBS ON CACHE STRING "ON or OFF" )
# don't include boost mysql library as it does a find_package(OpenSSL) thus finding the system openssl which could conflict with the bundled boringssl
set( BOOST_EXCLUDE_LIBRARIES "mysql" )

add_subdirectory( boost EXCLUDE_FROM_ALL )
add_subdirectory( libfc )
add_subdirectory( chainbase )