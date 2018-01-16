//===- FuzzerMain.cpp - main() function and flags -------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// main() and flags.
//===----------------------------------------------------------------------===//

#include "FuzzerDefs.h"

extern "C" {
// This function should be defined by the user.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#if LIBFUZZER_WINDOWS
int FuzzerMain(int argc, char **argv) {
  return fuzzer::FuzzerDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}
}   // extern "C"
#else
}   // extern "C"
int main(int argc, char **argv) {
  return fuzzer::FuzzerDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}
#endif // LIBFUZZER_WINDOWS



