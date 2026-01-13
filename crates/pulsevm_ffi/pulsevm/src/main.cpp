#include <boost/asio/ip/tcp.hpp>
#include <pulsevm/types.hpp>
#include <cstdio>

int main(int argc, const char** argv) {
    using namespace std::literals::string_view_literals;
    if (argc == 2 && "--version"sv == argv[1]) {
          std::printf("pulsevm@%s", eosio::version::version_full().c_str());
          return 0;
    }
}
