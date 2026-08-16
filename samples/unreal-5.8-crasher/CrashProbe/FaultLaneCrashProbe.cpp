extern "C" __declspec(dllexport) __declspec(noinline) void FaultLaneCrashPrimary()
{
    *static_cast<volatile int*>(nullptr) = 1;
}

extern "C" __declspec(dllexport) __declspec(noinline) void FaultLaneCrashSecondary()
{
    *static_cast<volatile int*>(nullptr) = 2;
}
