#!/bin/sh
# Regenerates the real-world NuGet conformance case: the .NET SDK restores a solution with central
# package management (transitive pinning, a floating version), Directory.Build.props, two projects
# with a project reference, two target frameworks, a runtime identifier, a framework-conditional
# reference, and a local feed served through package source mapping. `dotnet list package
# --include-transitive --format json` is the authoritative inventory. Nothing is built or run.
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" mcr.microsoft.com/dotnet/sdk:8.0 sh /conformance/generate/nuget.sh
set -eu
OUT=/conformance/cases/nuget/real-central-management
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
command -v python3 >/dev/null || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3 >/dev/null 2>&1; }
rm -rf /tmp/n && mkdir -p /tmp/n/src/App /tmp/n/src/Core /tmp/n/internal/Acme.Internal.Util /tmp/n/local-feed && cd /tmp/n

# An internal package, packed into a folder feed that source mapping routes `Acme.*` to.
cat > internal/Acme.Internal.Util/Acme.Internal.Util.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>netstandard2.0</TargetFramework>
    <Version>1.4.0</Version>
    <Authors>conformance</Authors>
  </PropertyGroup>
</Project>
EOF
(cd internal/Acme.Internal.Util && dotnet pack -c Release -o /tmp/n/local-feed -p:ManagePackageVersionsCentrally=false >/dev/null)
rm -rf internal

cat > NuGet.Config <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
    <add key="acme-local" value="./local-feed" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
    <packageSource key="acme-local">
      <package pattern="Acme.*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
EOF

cat > Directory.Build.props <<'EOF'
<Project>
  <PropertyGroup>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.SourceLink.GitHub" PrivateAssets="All" />
  </ItemGroup>
</Project>
EOF

cat > Directory.Packages.props <<'EOF'
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
    <CentralPackageTransitivePinningEnabled>true</CentralPackageTransitivePinningEnabled>
    <CentralPackageFloatingVersionsEnabled>true</CentralPackageFloatingVersionsEnabled>
    <SerilogVersion>4.1.0</SerilogVersion>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.*" />
    <PackageVersion Include="Serilog" Version="$(SerilogVersion)" />
    <PackageVersion Include="Microsoft.Extensions.Logging" Version="8.0.1" />
    <PackageVersion Include="System.Text.Json" Version="8.0.5" />
    <PackageVersion Include="Microsoft.Bcl.AsyncInterfaces" Version="8.0.0" />
    <PackageVersion Include="xunit" Version="2.9.2" />
    <PackageVersion Include="Microsoft.SourceLink.GitHub" Version="8.0.0" />
    <PackageVersion Include="Acme.Internal.Util" Version="1.4.0" />
    <PackageVersion Include="Polly" Version="8.4.2" />
    <PackageVersion Include="System.Net.Http" Version="4.3.4" />
  </ItemGroup>
  <ItemGroup>
    <GlobalPackageReference Include="Nerdbank.GitVersioning" Version="3.6.146" />
  </ItemGroup>
</Project>
EOF

cat > src/Core/Core.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;netstandard2.0</TargetFrameworks>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Extensions.Logging" />
    <PackageReference Include="Acme.Internal.Util" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)' == 'netstandard2.0'">
    <PackageReference Include="System.Text.Json" />
  </ItemGroup>
</Project>
EOF

cat > src/App/App.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <RuntimeIdentifier>linux-x64</RuntimeIdentifier>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="../Core/Core.csproj" />
  </ItemGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" />
    <PackageReference Include="Serilog" />
    <PackageReference Include="Polly" VersionOverride="8.4.1" />
    <PackageReference Include="xunit" PrivateAssets="all" />
    <PackageReference Include="System.Net.Http" />
  </ItemGroup>
</Project>
EOF

dotnet new sln -n Conformance >/dev/null
dotnet sln add src/App/App.csproj src/Core/Core.csproj >/dev/null
dotnet restore Conformance.sln >/dev/null
dotnet list Conformance.sln package --include-transitive --format json > /tmp/listed.json

python3 - "$OUT" <<'PY'
import json, os, shutil, sys
out = sys.argv[1]
if os.path.isdir(out):
    for name in os.listdir(out):
        if name not in ("expect.yaml", "README.md"):
            path = os.path.join(out, name)
            shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
os.makedirs(out, exist_ok=True)
keep = [
    "NuGet.Config", "Directory.Build.props", "Directory.Packages.props", "Conformance.sln",
    "src/App/App.csproj", "src/App/packages.lock.json", "src/Core/Core.csproj", "src/Core/packages.lock.json",
    "src/App/obj/project.assets.json",
]
for relative in keep:
    os.makedirs(os.path.dirname(os.path.join(out, relative)) or out, exist_ok=True)
    shutil.copy(relative, os.path.join(out, relative))
os.makedirs(os.path.join(out, "local-feed"), exist_ok=True)
for name in os.listdir("local-feed"):
    shutil.copy(os.path.join("local-feed", name), os.path.join(out, "local-feed", name))
listed = json.load(open("/tmp/listed.json"))
truth, frameworks = set(), {}
for project in listed.get("projects", []):
    for framework in project.get("frameworks", []):
        for kind in ("topLevelPackages", "transitivePackages"):
            for package in framework.get(kind, []):
                coordinate = f"{package['id']}@{package['resolvedVersion']}"
                truth.add(coordinate)
                frameworks.setdefault(coordinate, set()).add(f"{os.path.basename(project['path'])}:{framework['framework']}")
json.dump(
    {
        "tool": "dotnet list package --include-transitive --format json",
        "packages": sorted(truth),
        "exclude": {
            "condition_prefix": {
                "runtime ": "dotnet list package reports the framework graphs only; packages restored for a runtime identifier are in packages.lock.json's <framework>/<rid> graph"
            }
        },
        "frameworks": {k: sorted(v) for k, v in sorted(frameworks.items())},
    },
    open(os.path.join(out, "authoritative.json"), "w"),
    indent=1,
)
print("listed", len(truth))
PY
head -40 src/App/packages.lock.json
echo done
