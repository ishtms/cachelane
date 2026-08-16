using UnrealBuildTool;

public class FaultLaneCrasher : ModuleRules
{
    public FaultLaneCrasher(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PublicDependencyModuleNames.AddRange(new[] { "Core", "CoreUObject", "Engine" });
    }
}
