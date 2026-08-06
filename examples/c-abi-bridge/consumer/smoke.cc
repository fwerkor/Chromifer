#include "examples/c-abi-bridge/include/api.h"

int ChromiferCAbiSmoke() {
  return chromifer_add(20, 22) == 42 ? 0 : 1;
}
