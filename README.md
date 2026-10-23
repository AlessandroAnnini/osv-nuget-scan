# osv-nuget-scan

Author: Alessandro Filippo Annini

[![skills.sh](https://skills.sh/b/AlessandroAnnini/osv-nuget-scan)](https://skills.sh/AlessandroAnnini/osv-nuget-scan)

Agent skill that matches NuGet package versions in a C# project against the [OSV.dev](https://osv.dev) API. The format follows the [Agent Skills specification](https://agentskills.io/specification), which is what [skills.sh](https://skills.sh) publishes.

```
osv-nuget-scan/
├── SKILL.md
├── LICENSE
├── scripts/osv-scan.mjs
├── scripts/osv-scan.test.mjs
└── references/report-schema.md
```

Requires Node.js 18 or newer and network access to `https://api.osv.dev` and `https://builds.dotnet.microsoft.com`. No packages to install. The `dotnet` CLI is used when it is on PATH.

```bash
node scripts/osv-scan.mjs /path/to/project
```

Stdout is one JSON document. The fields are described in `references/report-schema.md`.

The report also has a separate `runtime` section. It checks the runtimes from `dotnet --list-runtimes` against [Microsoft's release metadata](https://github.com/dotnet/core/tree/main/release-notes): security releases missed in each line, the CVEs those releases fixed, and the support phase and end-of-life date of each line. It also gives the support status of every `TargetFramework` in the scanned projects. To check another runtime, such as the one in your container image:

```bash
node scripts/osv-scan.mjs /path/to/project --dotnet-version 8.0.31
```

A `packages.lock.json` (lock file version 1, 2, or 3) supplies the full graph, including transitive packages. Without one, `obj/project.assets.json` from the last restore is used. Without either, the script queries exact `PackageReference` versions and central pins from `Directory.Packages.props`, and says that transitive packages were not queried. It does not restore the project and it does not write a lockfile.

```bash
node --test scripts/osv-scan.test.mjs
```

Install:

```bash
npx skills add AlessandroAnnini/osv-nuget-scan
```

## Other ecosystems

| Skill | Ecosystem | Manifest |
| --- | --- | --- |
| `osv-npm-scan` | npm | `package-lock.json` |
| `osv-nuget-scan` | NuGet | C# lockfiles and exact package pins |
| `osv-uv-scan` | PyPI | `uv.lock` |

`ecosystem` in the JSON is `NuGet` here. The finding, location, and advisory fields stay the same so a report from any of the skills can be read the same way.
