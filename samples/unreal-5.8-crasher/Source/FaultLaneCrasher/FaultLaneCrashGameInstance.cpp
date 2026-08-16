#include "FaultLaneCrashGameInstance.h"

#include "HAL/PlatformProcess.h"
#include "Misc/CommandLine.h"
#include "Misc/Paths.h"
#include "Misc/Parse.h"

void UFaultLaneCrashGameInstance::Init()
{
    Super::Init();
    if (!FParse::Param(FCommandLine::Get(), TEXT("FaultLaneCrash")))
    {
        return;
    }
    const TCHAR* ExportName = FParse::Param(FCommandLine::Get(), TEXT("FaultLaneCrashSecondary"))
        ? TEXT("FaultLaneCrashSecondary")
        : TEXT("FaultLaneCrashPrimary");
    const FString ProbePath = FPaths::Combine(FPlatformProcess::BaseDir(), TEXT("FaultLaneCrashProbe.dll"));
    void* Probe = FPlatformProcess::GetDllHandle(*ProbePath);
    if (Probe == nullptr)
    {
        UE_LOG(LogTemp, Fatal, TEXT("FaultLane sample crash probe could not be loaded"));
    }
    using FCrashFunction = void (*)();
    FCrashFunction Crash = reinterpret_cast<FCrashFunction>(FPlatformProcess::GetDllExport(Probe, ExportName));
    if (Crash == nullptr)
    {
        UE_LOG(LogTemp, Fatal, TEXT("FaultLane sample crash probe is invalid"));
    }
    Crash();
}
