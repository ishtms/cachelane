#include <Windows.h>
#include <DbgHelp.h>

__declspec(noinline) volatile LONG* CrashAddress()
{
    return nullptr;
}

__forceinline void RaiseFixtureException(volatile LONG* address)
{
    *address = 1;
}

__declspec(noinline) void CrashFixture()
{
    RaiseFixtureException(CrashAddress());
}

LONG WriteFixtureDump(EXCEPTION_POINTERS* exception)
{
    HANDLE output = CreateFileW(
        L"cachelane-symbolication.dmp",
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (output == INVALID_HANDLE_VALUE) {
        return EXCEPTION_EXECUTE_HANDLER;
    }

    MINIDUMP_EXCEPTION_INFORMATION information = {
        GetCurrentThreadId(),
        exception,
        FALSE,
    };
    MiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        output,
        MiniDumpNormal,
        &information,
        nullptr,
        nullptr);
    CloseHandle(output);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main()
{
    __try {
        CrashFixture();
    }
    __except (WriteFixtureDump(GetExceptionInformation())) {
        return 0;
    }
}
