using UnrealBuildTool;

public class FaultLaneCrasherEditorTarget : TargetRules
{
    public FaultLaneCrasherEditorTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Editor;
        DefaultBuildSettings = BuildSettingsVersion.Latest;
        ExtraModuleNames.Add("FaultLaneCrasher");
    }
}
