// test_framework.h — A tiny, dependency-free unit-test harness.
//
// Self-registering TEST(...) blocks plus CHECK macros. Compiles with any C++11
// compiler (no PlatformIO / Unity / GoogleTest needed), so the suite runs the
// same way on a developer laptop and in CI. See test/test_main.cpp for the
// runner and Makefile for the build.
#pragma once

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace artemisz_test {

struct TestCase {
  const char* name;
  std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> r;
  return r;
}
inline int& failCount() { static int f = 0; return f; }
inline int& checkCount() { static int c = 0; return c; }
inline const char*& currentTest() { static const char* t = ""; return t; }

struct Registrar {
  Registrar(const char* name, std::function<void()> fn) {
    registry().push_back({name, fn});
  }
};

// Compare two byte buffers; print a readable diff on mismatch.
inline bool bytesEqual(const uint8_t* a, const uint8_t* b, size_t n,
                       int line, const char* file) {
  checkCount()++;
  if (memcmp(a, b, n) == 0) return true;
  failCount()++;
  std::printf("  FAIL %s:%d [%s]: byte buffers differ\n", file, line,
              currentTest());
  for (size_t i = 0; i < n; i++) {
    if (a[i] != b[i]) {
      std::printf("        offset %zu: got 0x%02X, want 0x%02X\n", i, a[i],
                  b[i]);
    }
  }
  return false;
}

}  // namespace artemisz_test

#define TEST(name)                                                       \
  static void name();                                                    \
  static ::artemisz_test::Registrar reg_##name(#name, name);             \
  static void name()

#define CHECK(cond)                                                      \
  do {                                                                   \
    ::artemisz_test::checkCount()++;                                     \
    if (!(cond)) {                                                       \
      ::artemisz_test::failCount()++;                                    \
      std::printf("  FAIL %s:%d [%s]: CHECK(%s)\n", __FILE__, __LINE__,  \
                  ::artemisz_test::currentTest(), #cond);                \
    }                                                                    \
  } while (0)

#define CHECK_EQ(a, b)                                                   \
  do {                                                                   \
    ::artemisz_test::checkCount()++;                                     \
    long long _va = (long long)(a);                                      \
    long long _vb = (long long)(b);                                      \
    if (_va != _vb) {                                                    \
      ::artemisz_test::failCount()++;                                    \
      std::printf("  FAIL %s:%d [%s]: CHECK_EQ(%s, %s) -> %lld != %lld\n",\
                  __FILE__, __LINE__, ::artemisz_test::currentTest(),    \
                  #a, #b, _va, _vb);                                     \
    }                                                                    \
  } while (0)

#define CHECK_BYTES(a, b, n)                                             \
  ::artemisz_test::bytesEqual((const uint8_t*)(a), (const uint8_t*)(b),  \
                              (n), __LINE__, __FILE__)
