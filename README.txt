# WinLibfuzzer

Run LLVM Libfuzzer on windows

## How to build

1. Download and install clang 5.0.0

2. run `build.sh`

## How to run LLVM Libfuzzer on windows

1. Download and install clang 5.0.0

2. choose the fuzzing target, usually a method like below

```c++
void FunctionToBeFuzzed(const uint8_t *data, size_t size) {
    if (size > 0 && data[0] == 'H') {
        if (size > 1 && data[1] == 'I') {
            __builtin_trap();
        }  
    }
}
```

3. write fuzzer code based on LLVM Libfuzzer API, see below example
```c++
extern "C" {
     
int FuzzerMain(int argc, char **argv);
     
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FunctionToBeFuzzed(data, size);
    return 0;
    }
}
 
int main(int argc, char **argv) {
    return FuzzerMain(argc, argv);
}


4. compile with the static library from this repo.
I put the target code and fuzzing code in step 1 into a single cpp SimpleTest.cpp for demonstration only, then run below command
```
clang.exe -fsanitize=address -fsanitize-coverage=trace-pc-guard fuzzer.lib SimpleTest.cpp -o SimpleTest.exe
```
```

5. run generated fuzzing binary
```
C:\Users\test\compiler-rt-master\lib\fuzzer\test>SimpleTest.exe
INFO: Seed: 2274119799
INFO: Loaded 1 modules   (10028 guards): 10028 [00007FF6512E6000, 00007FF6512EFCB0),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 1945 ft: 168 corp: 1/1b exec/s: 0 rss: 66Mb
#3      NEW    cov: 2159 ft: 238 corp: 2/2b exec/s: 0 rss: 66Mb L: 1/1 MS: 1 ChangeBit-
#4      NEW    cov: 2226 ft: 273 corp: 3/4b exec/s: 0 rss: 66Mb L: 2/2 MS: 2 ChangeBit-CopyPart-
#5      NEW    cov: 2230 ft: 290 corp: 4/6b exec/s: 0 rss: 66Mb L: 2/2 MS: 3 ChangeBit-CopyPart-ChangeByte-
#6      NEW    cov: 2252 ft: 306 corp: 5/4102b exec/s: 0 rss: 66Mb L: 4096/4096 MS: 4 ChangeBit-CopyPart-ChangeByte-CrossOver-
#7      NEW    cov: 2256 ft: 316 corp: 6/8198b exec/s: 0 rss: 66Mb L: 4096/4096 MS: 5 ChangeBit-CopyPart-ChangeByte-CrossOver-ChangeByte-
#8      NEW    cov: 2262 ft: 332 corp: 7/8199b exec/s: 0 rss: 66Mb L: 1/4096 MS: 1 ChangeBit-
#9      NEW    cov: 2270 ft: 336 corp: 8/8200b exec/s: 0 rss: 66Mb L: 1/4096 MS: 2 ChangeBit-ChangeBit-
#10     NEW    cov: 2271 ft: 347 corp: 9/8202b exec/s: 0 rss: 66Mb L: 2/4096 MS: 3 ChangeBit-ChangeBit-InsertByte-
#11     NEW    cov: 2299 ft: 355 corp: 10/12298b exec/s: 0 rss: 66Mb L: 4096/4096 MS: 4 ChangeBit-ChangeBit-InsertByte-CrossOver-
#13     NEW    cov: 2325 ft: 357 corp: 11/16Kb exec/s: 0 rss: 66Mb L: 4096/4096 MS: 1 CrossOver-
#14     NEW    cov: 2326 ft: 363 corp: 12/20Kb exec/s: 0 rss: 66Mb L: 4096/4096 MS: 2 CrossOver-ShuffleBytes-
#183    NEW    cov: 2534 ft: 367 corp: 13/24Kb exec/s: 0 rss: 67Mb L: 4096/4096 MS: 1 CrossOver-
#318    NEW    cov: 2545 ft: 368 corp: 14/26Kb exec/s: 0 rss: 67Mb L: 2415/4096 MS: 1 EraseBytes-
#319    NEW    cov: 2545 ft: 374 corp: 15/28Kb exec/s: 0 rss: 67Mb L: 2415/4096 MS: 2 EraseBytes-CopyPart-
#4646   NEW    cov: 2588 ft: 385 corp: 16/28Kb exec/s: 0 rss: 78Mb L: 3/4096 MS: 4 ShuffleBytes-ChangeBit-CMP-ChangeByte- DE: "\xff\xff"-
#6912   NEW    cov: 2607 ft: 394 corp: 17/32Kb exec/s: 6912 rss: 83Mb L: 3493/4096 MS: 5 ChangeBinInt-CrossOver-ChangeBit-ShuffleBytes-EraseBytes-
#10386  NEW    cov: 2611 ft: 398 corp: 18/32Kb exec/s: 10386 rss: 91Mb L: 1/4096 MS: 4 InsertByte-ChangeBinInt-EraseBytes-EraseBytes-
#10418  NEW    cov: 2611 ft: 402 corp: 19/32Kb exec/s: 10418 rss: 91Mb L: 1/4096 MS: 1 ShuffleBytes-
#10419  NEW    cov: 2615 ft: 405 corp: 20/32Kb exec/s: 10419 rss: 91Mb L: 5/4096 MS: 2 ShuffleBytes-CMP- DE: "\xff\xff\xff\xff"-
#10420  NEW    cov: 2618 ft: 410 corp: 21/32Kb exec/s: 10420 rss: 91Mb L: 5/4096 MS: 3 ShuffleBytes-CMP-ChangeBit- DE: "\xff\xff\xff\xff"-
#10422  NEW    cov: 2618 ft: 413 corp: 22/32Kb exec/s: 10422 rss: 91Mb L: 5/4096 MS: 5 ShuffleBytes-CMP-ChangeBit-ChangeByte-ChangeBit- DE: "\xff\xff\xff\xff"-
#16384  pulse  cov: 2619 ft: 413 corp: 22/32Kb exec/s: 8192 rss: 105Mb
==4540== ERROR: libFuzzer: deadly signal
    #0 0x7ff64f0ad7a4 in __sanitizer_print_stack_trace C:\src\llvm_package_500\llvm\projects\compiler-rt\lib\asan\asan_stack.cc:38
    #1 0x7ff64f1820f7 in fuzzer::Fuzzer::CrashCallback+0x147 (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x1400f20f7)
    #2 0x7ff64f181f9d in fuzzer::Fuzzer::StaticCrashSignalCallback+0x6d (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x1400f1f9d)
    #3 0x7ff64f1ca2a2 in fuzzer::SetSignalHandler+0xcf2 (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x14013a2a2)
    #4 0x7ffe79967e2d in UnhandledExceptionFilter+0x1ad (C:\WINDOWS\system32\KERNELBASE.dll+0x1800c7e2d)
    #5 0x7ffe7cebd957 in memset+0x2097 (C:\WINDOWS\SYSTEM32\ntdll.dll+0x1800ad957)
    #6 0x7ffe7cea5ac5 in _C_specific_handler+0x95 (C:\WINDOWS\SYSTEM32\ntdll.dll+0x180095ac5)
    #7 0x7ffe7ceb9a9c in _chkstk+0xfc (C:\WINDOWS\SYSTEM32\ntdll.dll+0x1800a9a9c)
    #8 0x7ffe7ce44f28 in RtlImageNtHeaderEx+0x4b8 (C:\WINDOWS\SYSTEM32\ntdll.dll+0x180034f28)
    #9 0x7ffe7ceb8ba9 in KiUserExceptionDispatcher+0x39 (C:\WINDOWS\SYSTEM32\ntdll.dll+0x1800a8ba9)
    #10 0x7ff64f09118e in hi+0x18e (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x14000118e)
    #11 0x7ff64f0911df in LLVMFuzzerTestOneInput+0x3f (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x1400011df)
    #12 0x7ff64f1860a9 in fuzzer::Fuzzer::ExecuteCallback+0x659 (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x1400f60a9)
    #13 0x7ff64f18470b in fuzzer::Fuzzer::RunOne+0x31b (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x1400f470b)
    #14 0x7ff64f188a60 in fuzzer::Fuzzer::MutateAndTestOne+0xab0 (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x1400f8a60)
    #15 0x7ff64f18d06f in fuzzer::Fuzzer::Loop+0x102f (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x1400fd06f)
    #16 0x7ff64f13ea3c in fuzzer::FuzzerDriver+0x449c (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x1400aea3c)
    #17 0x7ff64f0ef7bd in FuzzerMain+0x19d (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x14005f7bd)
    #18 0x7ff64f091235 in main+0x45 (C:\Users\test\compiler-rt-master\lib\fuzzer\test\SimpleTest.exe+0x140001235)
    #19 0x7ff64f255730 in __scrt_common_main_seh f:\dd\vctools\crt\vcstartup\src\startup\exe_common.inl:253
    #20 0x7ffe7a228101 in BaseThreadInitThunk+0x21 (C:\WINDOWS\system32\KERNEL32.DLL+0x180018101)
    #21 0x7ffe7ce6c573 in RtlUserThreadStart+0x33 (C:\WINDOWS\SYSTEM32\ntdll.dll+0x18005c573)
 
NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 4 InsertByte-EraseBytes-CopyPart-ChangeBit-; base unit: 835537ca65873cf23424696e78de2a6f1e803711
0x48,0x49,0xff,0x8f,0xff,0xff,0x8f,0xff,0xff,
HI\xff\x8f\xff\xff\x8f\xff\xff
artifact_prefix='./'; Test unit written to ./crash-56333fed4d6d0387783e2eff4d906ea5bb9175ac
Base64: SEn/j///j///
```