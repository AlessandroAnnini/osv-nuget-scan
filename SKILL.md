---
name: osv-nuget-scan
description: >-
  Scans C# and .NET projects for known vulnerabilities by matching NuGet
  package versions against the OSV.dev API. Use whenever the user asks about
  vulnerabilities, CVEs, security advisories, dependency risk, NuGet audit, or
  whether a C#, .NET, or NuGet project is affected, including when they mention
  packages.lock.json, Directory.Packages.props, PackageReference, a .csproj, or
  osv.dev. Also checks the .NET runtime against Microsoft's release metadata,
  so use it when the user asks whether their .NET version or target framework
  is vulnerable, out of support, or end of life. Do not use this skill for
  Node, npm, JavaScript, Python, or PyPI projects.
license: MIT
compatibility: Requires Node.js 18 or newer and network access to https://api.osv.dev and https://builds.dotnet.microsoft.com. Uses the dotnet CLI when it is on PATH. Reads NuGet packages.lock.json versions 1, 2, and 3, project.assets.json, packages.config, and exact PackageReference versions.
metadata:
  author: Alessandro Filippo Annini
  version: "1.2.0"
  ecosystem: NuGet
---

# osv-nuget-scan

Match NuGet package versions in a C# project against [OSV.dev](https://osv.dev). Report the advisories the API returns. Do not reimplement the scan, and do not edit the script.

This skill is the NuGet member of a set. It emits the same JSON shape as `osv-npm-scan`, documented in [references/report-schema.md](references/report-schema.md).

## Run

From any working directory, run the script that sits next to this file. The argument is the project root:

```bash
node /absolute/path/to/osv-nuget-scan/scripts/osv-scan.mjs /absolute/path/to/project
```

The script writes one JSON document to stdout and progress lines to stderr. It does not modify the project. Do not run `dotnet restore`, and do not write `packages.lock.json`, unless the user asks.

By default the runtime check reads `dotnet --list-runtimes` on the machine running the scan. To check the runtime the project deploys on, such as a container image or a self-contained app, pass its `Microsoft.NETCore.App` version:

```bash
node /absolute/path/to/osv-nuget-scan/scripts/osv-scan.mjs /absolute/path/to/project --dotnet-version 8.0.31
```

Pass `--dotnet-version` only with an exact version the user gave or the project pins exactly. Do not turn `net8.0` or a `global.json` SDK into a runtime patch version.

If stdout contains an `error` field, say what it says and stop. A project with no package versions is not a clean scan. If `warnings` is present, say each warning before the findings.

## What the script covers

- Every `packages.lock.json` under the project root (NuGet lock file versions 1, 2, and 3), except paths inside `bin`, `obj`, `node_modules`, or `.git`, and except files reached only through a symlink. This is the graph that gets queried when it is present
- Otherwise `obj/project.assets.json` beside the project, when `restore.projectUniqueName` is that project. A literal `IntermediateOutputPath` or `BaseIntermediateOutputPath` with no MSBuild property in it is honored. The file is the last restore, including transitive packages. When it is older than the project file, the report says so
- Otherwise exact versions from `packages.config`
- Otherwise exact versions on `PackageReference` and `GlobalPackageReference` in the project, in the nearest `Directory.Build.props`, and in the nearest `Directory.Packages.props`. Those two files are found by walking parent directories, including above the scan root, the same way MSBuild does. A file that imports another file of the same name also contributes that parent. A missing `Version` is taken from `PackageVersion` in `Directory.Packages.props`
- Direct and transitive packages in a lockfile or an assets file. `CentralTransitive` is transitive. `Project` entries are project references, not packages

Separately, the script checks the .NET runtime against [Microsoft's release metadata](https://github.com/dotnet/core/tree/main/release-notes). The result is in `runtime`. It is not in `findings` and does not count toward `vulnerablePackageVersions`. It has two parts:

- `installed`: each shared framework (`Microsoft.NETCore.App`, `Microsoft.AspNetCore.App`, `Microsoft.WindowsDesktop.App`) from `dotnet --list-runtimes`, or the one version from `--dotnet-version`. Each is compared on its own version with the security releases in its line. Apps roll forward to the highest patch of a line, so only `active` entries decide `runtime.vulnerable`
- `targets`: every `TargetFramework` and `TargetFrameworks` value in the scanned projects, with the support phase and end-of-life date of its line. `net4x` is .NET Framework, which Windows Update services. It is named and not checked. `netstandard` is not a runtime

`1.2.3`, `[1.2.3]`, and `[1.2.3, 1.2.3]` are exact versions. A range or a floating version is skipped, with a warning. A version that is only `$(Name)` is replaced from a property in those same files. The script does not evaluate MSBuild conditions or any other expression, and it does not resolve a range against nuget.org. A `PackageVersion` that no project references is not an install. `PackageReference Remove` drops a package inherited from a props file.

A project is a test project when `IsTestProject` is true, when the file name is `Test.csproj` or `Tests.csproj`, or ends in `.Test(s).csproj`, `.UnitTest(s).csproj`, `.IntegrationTest(s).csproj`, `.FunctionalTest(s).csproj`, `.EndToEndTest(s).csproj`, or `.E2ETest(s).csproj`, or when it references `Microsoft.NET.Test.Sdk`, MSTest, xunit, NUnit, or TUnit. `Microsoft.Testing.Platform` alone does not make a project a test project. Packages that appear only on a test project are dev-only. NuGet has no per-package dev flag inside a lockfile, so a package in an application project stays production even when `PrivateAssets` is `all`.

## How to report

Read [references/report-schema.md](references/report-schema.md) before summarizing.

Lead with the answer: whether any queried version is in an OSV advisory, how many package versions were queried, and how many of those versions have at least one advisory.

When a warning says transitive dependencies were not queried, say that before the table. The counts then cover only the direct pins. Do not invent transitive packages. Tell the user that a committed `packages.lock.json` (`RestorePackagesWithLockFile`) is what would include them, and do not generate one unless they ask.

Then a table of production findings at CRITICAL and HIGH, one row per package version:

- Package and locked or pinned version
- Manifest, and whether it is a direct production dependency
- `introducedBy` when it is transitive
- Worst advisory id, a short summary, and `upgradeTo`

`severity` on a finding is already the worst advisory. `MEDIUM` means GitHub's MODERATE. Do not rescore advisories from the CVSS vector. `score` is informational.

When advisories on the same version disagree by major (one fixed in 4.x, another only in 5.x), name the advisory that forces `upgradeTo`. When `upgradeTo` is null, an advisory has no fixed version. Report the highest `fixed` among the advisories that have one, and name the advisory that has none.

Mention dev-only CRITICAL and HIGH findings in a short paragraph after the production table. Count the remaining MEDIUM and LOW production findings instead of listing every advisory. Call out a direct production dependency in that remainder when there is one.

Then the runtime, in its own short section:

- Name the checked versions and `runtime.source`. When the source is `process`, say these are the runtimes on the machine that ran the scan, and may not be what the project deploys on. When `runtime.note` says `dotnet` was not found, say no installed runtime was checked
- For each `active` installed runtime with `vulnerable` true: the version, how many security releases it is behind, the CVE count, and `upgradeTo`. `cves` come from whole releases, so call them CVEs fixed in newer releases, not CVEs proven to affect this framework. The metadata has no severity. Do not invent one
- For each line that is end of life, among the installed runtimes and the targets, say it is unsupported whatever the CVE count. An end-of-life line gets no more security releases, so zero missed releases does not mean safe. Recommend `runtime.latestLts` instead of a patch
- When a line's `supportPhase` is `maintenance`, give its `endOfLifeDate`. Call it out when that date is close
- Name targets that were not checked, such as .NET Framework, in one line
- When `runtime.error` is present, say the runtime was not checked and why

This is a version match against known advisories. It does not show whether the vulnerable code runs. Say that once.

Do not upgrade packages unless the user asks.
