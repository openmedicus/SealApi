SEALAPI_VERSION = 2.0.7
ASSEMBLY_NAME = SealApi
ASSEMBLY = $(ASSEMBLY_NAME).dll

# nuget setApiKey 4f31ad55-...... -Source https://www.nuget.org/api/v2/package
nuget-release: SealApi/bin/Release/$(ASSEMBLY_NAME).$(SEALAPI_VERSION).nupkg
	nuget push SealApi/bin/Release/$(ASSEMBLY_NAME).$(SEALAPI_VERSION).nupkg -Source https://www.nuget.org/api/v2/package
