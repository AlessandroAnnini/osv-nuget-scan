# Report schema

`scripts/osv-scan.mjs` prints this document to stdout. The fields match `osv-npm-scan`. `ecosystem` is `NuGet`, and `lockfiles` lists the manifest that supplied each version.

## Success

```json
{
  "ecosystem": "NuGet",
  "scannedAt": "2026-10-23T08:00:00.000Z",
  "root": "/absolute/project",
  "lockfiles": ["src/App/App.csproj"],
  "packageVersions": 21,
  "vulnerablePackageVersions": 4,
  "warnings": [
    "only exact direct versions were queried for src/App/App.csproj, so transitive NuGet dependencies were not queried"
  ],
  "findings": []
}
```

`packageVersions` is the number of distinct name@version pairs sent to OSV. `vulnerablePackageVersions` counts those that have at least one current advisory. Withdrawn advisories are omitted.

Findings are sorted with production installs first, then by severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN), then by name.

`lockfiles` contains `packages.lock.json` or `project.assets.json` when that file supplied the graph. Otherwise the entry is `packages.config` or the `.csproj` whose `PackageReference` pins were queried. A `PackageVersion` that no project references is not an entry.

`warnings` is present when a file was skipped, a version was not exact, transitive packages were not queried, or a central pin was not referenced. Each entry is one sentence.

### Finding

| Field | Meaning |
| --- | --- |
| `name`, `version` | NuGet package id and the version that was queried |
| `severity` | Worst advisory label on this version |
| `upgradeTo` | Highest per-advisory fix. Null when any advisory has no fixed version |
| `locations` | One entry per manifest that installs this version |
| `advisories` | One entry per advisory, aliases already collapsed |

### Location

| Field | Meaning |
| --- | --- |
| `lockfile` | Path relative to `root` |
| `production` | True when the manifest belongs to a project that is not a test project. A test project has `IsTestProject` set to true, a file name of `Test(s).csproj` or ending in `.Test(s).csproj`, `.UnitTest(s).csproj`, `.IntegrationTest(s).csproj`, `.FunctionalTest(s).csproj`, `.EndToEndTest(s).csproj`, or `.E2ETest(s).csproj`, or a reference to `Microsoft.NET.Test.Sdk`, MSTest, xunit, NUnit, or TUnit |
| `direct` | True for a direct package in a lockfile or assets file, and for every `packages.config` or `PackageReference` pin. `Transitive` and `CentralTransitive` are false |
| `directProduction` | True when `direct` and `production` are both true |
| `introducedBy` | Direct package ids that pull this package in, from a lockfile or `project.assets.json`. Empty when `direct` is true, and empty when the manifest has no dependency graph |

A package referenced by an application project and a test project has two locations. The finding is production when any location has `production` true.

### Advisory

| Field | Meaning |
| --- | --- |
| `id` | Preferred id. A GHSA id when one exists, otherwise the first id |
| `aliases` | Other ids for the same advisory, including CVEs |
| `summary` | OSV summary |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN`. `MEDIUM` is GitHub MODERATE. A publisher label wins over a score computed from an alias that has no label |
| `score` | Highest CVSS v3 base score on the merged advisory. Null when neither a v3 vector nor a numeric score is present. Does not change `severity` |
| `fixed` | Lowest fixed version above the installed version for this advisory, compared with NuGet version rules (four numeric parts, then pre-release labels). Null when OSV lists no NuGet fix above the installed version. Fixes for other ecosystems on the same advisory are ignored |
| `url` | `https://osv.dev/vulnerability/<id>` |

`upgradeTo` is the highest `fixed` among advisories that have one, and only when every advisory has a fix. It assumes each advisory stays fixed after that version. NuGet comparison treats `1.0.0` and `1.0.0.0` as equal, and `1.0.0.1` as higher than `1.0.0`.

## Error

Exit code 1. Stdout is still JSON:

```json
{
  "ecosystem": "NuGet",
  "error": "no NuGet package versions found under /absolute/project"
}
```
