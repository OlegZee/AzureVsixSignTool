#!/bin/bash
dotnet restore

dotnet build ./src/OpenVsixSignTool.Core
dotnet build ./src/OpenVsixSignTool

dotnet test ./tests/OpenVsixSignTool.Tests/OpenVsixSignTool.Tests.csproj
dotnet test ./tests/OpenVsixSignTool.Core.Tests/OpenVsixSignTool.Core.Tests.csproj

dotnet build -c Release ./src/OpenVsixSignTool
dotnet pack -c Release ./src/OpenVsixSignTool

dotnet nuget push ./src/OpenVsixSignTool/nupkg/AzureVsixSignTool.0.1.1.nupkg --source https://www.nuget.org/api/v2/package --api-key oy2i3kpla...
