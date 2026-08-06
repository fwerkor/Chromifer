#include "examples/c-abi-bridge/include/api.h"

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>

int ChromiferCAbiSmoke();

namespace {

struct AddCase {
  int32_t left;
  int32_t right;
  int32_t expected;
};

int CheckAddMatrix() {
  constexpr AddCase kCases[] = {
      {0, 0, 0},
      {20, 22, 42},
      {-20, 22, 2},
      {123456, -65432, 58024},
      {std::numeric_limits<int32_t>::max(), -1,
       std::numeric_limits<int32_t>::max() - 1},
      {std::numeric_limits<int32_t>::min(), 1,
       std::numeric_limits<int32_t>::min() + 1},
  };

  for (std::size_t index = 0; index < std::size(kCases); ++index) {
    const AddCase& test = kCases[index];
    if (chromifer_add(test.left, test.right) != test.expected) {
      return 10 + static_cast<int>(index);
    }
  }

  for (int32_t index = 0; index < 1024; ++index) {
    const int32_t left = index - 512;
    const int32_t right = (index % 17) - 8;
    if (chromifer_add(left, right) != left + right) {
      return 20;
    }
  }
  return 0;
}

struct BufferCase {
  const uint8_t* data;
  uintptr_t length;
  bool expected;
};

int CheckBufferMatrix() {
  const uint8_t bytes[] = {0, 1, 2, 3};
  const BufferCase cases[] = {
      {nullptr, 0, false},
      {nullptr, 1, false},
      {bytes, 0, false},
      {bytes, 1, true},
      {bytes, std::size(bytes), true},
      {bytes + 3, 1, true},
  };

  for (std::size_t index = 0; index < std::size(cases); ++index) {
    const BufferCase& test = cases[index];
    if (chromifer_buffer_is_valid(test.data, test.length) != test.expected) {
      return 40 + static_cast<int>(index);
    }
  }
  return 0;
}

}  // namespace

int main() {
  if (const int smoke = ChromiferCAbiSmoke(); smoke != 0) {
    return smoke;
  }
  if (const int add = CheckAddMatrix(); add != 0) {
    return add;
  }
  return CheckBufferMatrix();
}
