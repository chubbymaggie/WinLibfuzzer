if exist "\build" rd /q /s "\build"
cd build
clang -c ..\*.cpp
lib *.o /OUT:fuzzer.lib
del *.o