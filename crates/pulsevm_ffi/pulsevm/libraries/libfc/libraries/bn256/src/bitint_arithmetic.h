#pragma once

#include <bit>
#include <cstdint>
#include <cstring>
#include <type_traits>

static_assert(std::endian::native == std::endian::little, "This library only supports little endian architecture");

#if defined(__amd64__)
#   include <x86intrin.h>
#endif
#include <iostream>

namespace bn256 {
constexpr bool subborrow_u64(bool carry, uint64_t a, uint64_t b, uint64_t* c) noexcept {
#if defined(__amd64__)
   if (!std::is_constant_evaluated()) {
      return _subborrow_u64(carry, a, b, (unsigned long long*)c);
   }
#elif defined(__clang__)
   if (!std::is_constant_evaluated()) {
      unsigned long long carryout=0;
      *c = __builtin_subcll(a, b, carry, &carryout);
      return carryout;
   }
#endif

   carry = __builtin_sub_overflow(a, carry, c);
   carry |= __builtin_sub_overflow(*c, b, c);
   return carry;
}

constexpr bool addcarry_u64(bool carry, uint64_t a, uint64_t b, uint64_t* c) noexcept {
#if defined(__amd64__)
   if (!std::is_constant_evaluated()) {
      return _addcarry_u64(carry, a, b, (unsigned long long*)c);
   }
#elif defined(__clang__)
   if (!std::is_constant_evaluated()) {
      unsigned long long carryout=0;
      *c = __builtin_addcll(a, b, carry, &carryout);
      return carryout;
   }
#endif
   carry = __builtin_add_overflow(a, carry, c);
   carry |= __builtin_add_overflow(*c, b, c);
   return carry;
}

constexpr uint64_t mulx_u64(uint64_t a, uint64_t b, uint64_t* hi) noexcept {
#ifdef __BMI2__
   if (!std::is_constant_evaluated()) {
      unsigned long long local_hi=0;
      auto r = _mulx_u64(a, b,&local_hi);
      memcpy(hi, &local_hi, sizeof(*hi));
      return r;
   }
#endif
   __uint128_t x = a;
   x *= b;
   *hi = static_cast<uint64_t>(x >> 64);
   return static_cast<uint64_t>(x & 0xFFFFFFFFFFFFFFFFULL);
}

constexpr bool subborrow_u256(bool carry, const uint64_t* a, const uint64_t* b, uint64_t* c) noexcept {
   carry = subborrow_u64(carry, a[0], b[0], &c[0]);
   carry = subborrow_u64(carry, a[1], b[1], &c[1]);
   carry = subborrow_u64(carry, a[2], b[2], &c[2]);
   carry = subborrow_u64(carry, a[3], b[3], &c[3]);
   return carry;
}


constexpr bool subborrow_u512(bool carry, const uint64_t* a, const uint64_t* b, uint64_t* c) noexcept {
   carry = subborrow_u256(carry, &a[0], &b[0], &c[0]);
   carry = subborrow_u256(carry, &a[4], &b[4], &c[4]);
   return carry;
}

constexpr bool addcarry_u256(bool carry, const uint64_t* a, const uint64_t* b, uint64_t* c) noexcept {
   carry = addcarry_u64(carry, a[0], b[0], &c[0]);
   carry = addcarry_u64(carry, a[1], b[1], &c[1]);
   carry = addcarry_u64(carry, a[2], b[2], &c[2]);
   carry = addcarry_u64(carry, a[3], b[3], &c[3]);
   return carry;
}


constexpr bool addcarry_u512(bool carry, const uint64_t* a, const uint64_t* b, uint64_t* c) noexcept {
   carry = addcarry_u256(carry, &a[0], &b[0], &c[0]);
   carry = addcarry_u256(carry, &a[4], &b[4], &c[4]);
   return carry;
}

[[gnu::always_inline]] [[gnu::hot]] constexpr void full_mul_u256(const uint64_t* a, const uint64_t* b,
                                                                 uint64_t* c) noexcept {
#ifdef BN256_HAS_EXTINT
   if (!std::is_constant_evaluated()) {
#if __clang__ && __clang_major__ >= 14
      using extint_t = _BitInt(512);
#else
      using extint_t = _ExtInt(512);
#endif
      extint_t x = 0, y = 0;
      memcpy(&x, a, sizeof(uint64_t) * 4);
      memcpy(&y, b, sizeof(uint64_t) * 4);
      extint_t z = x * y;
      memcpy(c, &z, sizeof(uint64_t) * 8);
      return;
   }
#endif
   // the code below is transcribed from the x86-64 assembly produced by Clang-13 using above _ExtInt feature
   uint64_t ax = 0, bx = 0, cx = 0, dx = 0, rsi = 0;
   uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0, rbp = 0;
   bool     carry = false;
   r9    = mulx_u64(b[2], a[0], &r10);
   bx    = mulx_u64(b[3], a[0], &cx);
   carry = addcarry_u64(false, r10, bx, &bx);
   carry = addcarry_u64(carry, 0, cx, &cx);
   r13   = mulx_u64(b[2], a[1], &ax);
   carry = addcarry_u64(false, bx, r13, &r13);
   cx    = addcarry_u64(carry, cx, ax, &ax);
   r12   = mulx_u64(b[3], a[1], &r15);
   carry = addcarry_u64(false, ax, r12, &r12);
   carry = addcarry_u64(carry, cx, r15, &r15);

   c[0]  = mulx_u64(b[0], a[0], &ax);
   rbp   = mulx_u64(b[1], a[0], &r14);
   carry = addcarry_u64(false, ax, rbp, &rbp);
   carry = addcarry_u64(carry, 0, r14, &r14);
   dx    = mulx_u64(b[0], a[1], &ax);
   carry = addcarry_u64(false, rbp, dx, &c[1]);
   r14   = addcarry_u64(carry, r14, ax, &ax);
   r10   = mulx_u64(b[1], a[1], &rbp);
   carry = addcarry_u64(false, ax, r10, &r10);
   ax    = r14;
   addcarry_u64(carry, ax, rbp, &rbp);
   carry = addcarry_u64(false, r9, r10, &r10);
   carry = addcarry_u64(carry, r13, rbp, &rbp);
   carry = addcarry_u64(carry, 0, r12, &r12);
   carry = addcarry_u64(carry, 0, r15, &r15);

   r14   = mulx_u64(b[0], a[2], &ax);
   r11   = mulx_u64(b[1], a[2], &r8);
   carry = addcarry_u64(false, ax, r11, &r11);
   carry = addcarry_u64(carry, 0, r8, &r8);
   cx    = mulx_u64(b[0], a[3], &r9);
   carry = addcarry_u64(false, r11, cx, &cx);
   dx    = addcarry_u64(carry, r8, r9, &r9);
   bx    = mulx_u64(b[1], a[3], &r11);
   carry = addcarry_u64(false, r9, bx, &bx);
   ax    = dx;
   carry = addcarry_u64(carry, dx, r11, &r11);
   carry = addcarry_u64(false, r10, r14, &c[2]);
   carry = addcarry_u64(carry, rbp, cx, &c[3]);
   carry = addcarry_u64(carry, 0, bx, &bx);
   carry = addcarry_u64(carry, 0, r11, &r11);
   carry = addcarry_u64(false, r12, bx, &bx);
   carry = addcarry_u64(carry, r15, r11, &r11);

   r8    = mulx_u64(b[2], a[2], &r9);

   rbp   = mulx_u64(b[3], a[2], &r15);
   r10   = carry;
   carry = addcarry_u64(false, r9, rbp, &rbp);
   carry = addcarry_u64(carry, 0, r15, &r15);
   ax    = mulx_u64(b[2], a[3], &r9);
   carry = addcarry_u64(false, rbp, ax, &ax);
   carry = addcarry_u64(carry, r15, r9, &r9);
   rbp   = carry;
   dx    = mulx_u64(b[3], a[3], &rsi);
   carry = addcarry_u64(false, r9, dx, &dx);
   carry = addcarry_u64(carry, rbp, rsi, &rsi);
   carry = addcarry_u64(false, bx, r8, &c[4]);
   carry = addcarry_u64(carry, r11, ax, &c[5]);
   carry = addcarry_u64(carry, r10, dx, &c[6]);
   addcarry_u64(carry, 0, rsi, &c[7]);
}

[[gnu::always_inline]] [[gnu::hot]]
constexpr void half_mul_u256(const uint64_t* a, const uint64_t* b, uint64_t* c) noexcept {
#ifdef BN256_HAS_EXTINT
   if (!std::is_constant_evaluated()) {
#if __clang__ && __clang_major__ >= 14
      using extint_t = _BitInt(256);
#else
      using extint_t = _ExtInt(256);
#endif
      extint_t x = 0, y = 0;
      memcpy(&x, a, sizeof(uint64_t) * 4);
      memcpy(&y, b, sizeof(uint64_t) * 4);
      extint_t z = x * y;
      memcpy(c, &z, sizeof(uint64_t) * 4);
      return;
   }
#endif
   // the code below is transcribed from the x86-64 assembly produced by Clang-13 using above _ExtInt feature
   uint64_t r10=0, r14=0, rax=0, rbx=0, rcx=0, rdx=0, rsi=0, rdi=0;
   bool     carry = 0;

   r14   = mulx_u64(a[0], b[2], &rdx);
   rsi   = a[0] * b[3];
   carry = addcarry_u64(false, rsi, rdx, &rdx);
   rbx   = a[1] * b[2];
   carry = addcarry_u64(false, rdx, rbx, &rbx);
   r10   = mulx_u64(a[2], b[0], &rdx);
   rsi   = a[2] * b[1];
   carry = addcarry_u64(false, rsi, rdx, &rdx);
   rdi   = b[0] * a[3];
   carry = addcarry_u64(false, rdx, rdi, &rdi);
   carry = addcarry_u64(false, r14, r10, &r10);
   carry = addcarry_u64(carry, rbx, rdi, &rdi);

   c[0]  = mulx_u64(a[0], b[0], &rsi);
   rcx   = mulx_u64(b[1], a[0], &rbx);
   carry = addcarry_u64(false, rsi, rcx, &rcx);
   carry = addcarry_u64(carry, 0, rbx, &rbx);

   rax   = mulx_u64(b[0], a[1], &rsi);
   carry = addcarry_u64(false, rcx, rax, &c[1]);
   rcx   = addcarry_u64(carry, rbx, rsi, &rsi);
   rdx   = mulx_u64(a[1], b[1], &rbx);
   carry = addcarry_u64(false, rsi, rdx, &rdx);
   carry = addcarry_u64(carry, rcx, rbx, &rbx);
   carry = addcarry_u64(false, r10, rdx, &c[2]);
   carry = addcarry_u64(carry, rdi, rbx, &c[3]);
}

} // namespace bn256
