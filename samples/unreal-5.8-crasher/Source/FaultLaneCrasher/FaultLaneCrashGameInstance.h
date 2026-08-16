#pragma once

#include "CoreMinimal.h"
#include "Engine/GameInstance.h"
#include "FaultLaneCrashGameInstance.generated.h"

UCLASS()
class FAULTLANECRASHER_API UFaultLaneCrashGameInstance : public UGameInstance
{
    GENERATED_BODY()

public:
    virtual void Init() override;
};
