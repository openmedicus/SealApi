# SealApi

# Strong Sign

Since MonoDevelop is unable to StrongName Sign a DLL do this.

1) Build Release
2) Manually do: "sn -R bin/Release/SealApi.dll ..//SealApi.snk"
3) Go to menu "Build" and click "Create NuGet Package"

The DLL will now be StrongNamed.
