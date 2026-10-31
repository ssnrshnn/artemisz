// test_main.cpp — Runner for the native unit-test suite.
#include "test_framework.h"

int main() {
  using namespace artemisz_test;
  std::printf("Running %zu test(s)...\n", registry().size());
  for (auto& tc : registry()) {
    currentTest() = tc.name;
    int before = failCount();
    tc.fn();
    bool ok = (failCount() == before);
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", tc.name);
  }
  std::printf("\n%d check(s), %d failure(s)\n", checkCount(), failCount());
  return failCount() == 0 ? 0 : 1;
}
