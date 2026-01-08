

#include "bn256/bn256.h"

#include <chrono>
#include <iostream>


template <typename Fun>
void benchmark(const char* metric, int count, Fun&& fun) {
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();

    for (int i = 0; i < count; ++i)
        fun();

    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
    std::cout << metric << "\t" << elapsed/count << " ns\n";
}


int main(int, const char**) {


    benchmark("g1::scaler_base_multi", 10000, []() {
        std::array<uint64_t,4> k = { 0xee59376474886cb2, 0x08cbb7b5caaeb745, 0xed73ab693b6472c0, 0x26a6bf93998520e0 };
        bn256::g1::scalar_base_mult(k);
    });

    benchmark("g2::scaler_base_multi", 5000, []() {
         std::array<uint64_t,4> k = { 0x3851406aea252b4f, 0x21cb1e666869d8af, 0x5ab08c9973f01681, 0x201266baa5903baa };
        bn256::g2::scalar_base_mult(k);
    });

    benchmark("bn256 pair", 1000, []() { bn256::pair(bn256::g1::curve_gen, bn256::g2::twist_gen); });

    return 0;
}
