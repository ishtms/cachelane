using UnrealBuildTool;

public class FaultLaneCrasherTarget : TargetRules
{
    public FaultLaneCrasherTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Game;
        DefaultBuildSettings = BuildSettingsVersion.Latest;
        ExtraModuleNames.Add("FaultLaneCrasher");
    }
}
