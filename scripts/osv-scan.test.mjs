import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  collectAssetsData,
  collectLockfileData,
  collectProjectRefs,
  compareVersions,
  cvssV3,
  exactNuGetVersion,
  groupRecords,
  introducedBy,
  locationFor,
  lowestFix,
  projectIsTest,
  scanTree,
  summarizeGroup,
  upgradeTo,
  walkFiles,
} from "./osv-scan.mjs";

const HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N";

test("NuGet order treats the fourth part and a pre-release as significant", () => {
  assert.equal(compareVersions("1.0.0", "1.0.0.0"), 0);
  assert.equal(compareVersions("1.0.0", "1.0.0.1") < 0, true);
  assert.equal(compareVersions("1.0.0-beta", "1.0.0-BETA"), 0);
  assert.equal(compareVersions("1.0.0-alpha", "1.0.0") < 0, true);
  assert.equal(compareVersions("1.0.0-alpha", "1.0.0-alpha.1") < 0, true);
  assert.equal(compareVersions("1.0.0-1", "1.0.0-a") < 0, true);
  assert.equal(compareVersions("1.2.3", "not-a-version"), null);
});

test("the lowest fix is the next NuGet version above the install", () => {
  assert.equal(lowestFix(["1.0.0.1", "1.0.1", "2.0.0"], "1.0.0"), "1.0.0.1");
  assert.equal(lowestFix(["1.11.4", "1.12.0"], "1.11.0"), "1.11.4");
  assert.equal(lowestFix(["not-a-version", "1.2.3"], "1.2.3"), null);
});

test("upgradeTo is the highest fix, and null when any advisory has none", () => {
  assert.equal(upgradeTo([{ fixed: "1.0.0.2" }, { fixed: "1.0.1" }]), "1.0.1");
  assert.equal(upgradeTo([{ fixed: "1.2.0" }, { fixed: null }]), null);
});

test("a known CVSS v3 critical vector scores 9.8", () => {
  assert.equal(cvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvssV3(HIGH_VECTOR), 7.5);
});

test("GitHub MODERATE is kept when an alias only has a high CVSS vector", () => {
  const advisory = summarizeGroup(
    [
      {
        id: "GHSA-aaaa-bbbb-cccc",
        summary: "example",
        aliases: ["CVE-2026-1"],
        database_specific: { severity: "MODERATE" },
      },
      {
        id: "CVE-2026-1",
        aliases: ["GHSA-aaaa-bbbb-cccc"],
        severity: [{ type: "CVSS_V3", score: HIGH_VECTOR }],
      },
    ],
    "Newtonsoft.Json",
    "13.0.1",
  );
  assert.equal(advisory.severity, "MEDIUM");
  assert.equal(advisory.score, 7.5);
  assert.equal(advisory.id, "GHSA-aaaa-bbbb-cccc");
  assert.deepEqual(advisory.aliases, ["CVE-2026-1"]);
});

test("a fix is taken from the NuGet package on a multi-ecosystem advisory", () => {
  const advisory = summarizeGroup(
    [
      {
        id: "GHSA-m5vv-6r4h-3vj9",
        summary: "Azure Identity elevation of privilege",
        database_specific: { severity: "MODERATE" },
        affected: [
          {
            package: { name: "azure-identity", ecosystem: "PyPI" },
            ranges: [{ events: [{ fixed: "1.16.1" }] }],
          },
          {
            package: { name: "Azure.Identity", ecosystem: "NuGet" },
            ranges: [{ events: [{ introduced: "0" }, { fixed: "1.11.4" }] }],
          },
        ],
      },
    ],
    "Azure.Identity",
    "1.11.0",
  );
  assert.equal(advisory.fixed, "1.11.4");
  assert.equal(advisory.severity, "MEDIUM");
});

test("records that share an alias id collapse even when that id was not fetched", () => {
  const groups = groupRecords([
    { id: "GHSA-1111-2222-3333", aliases: ["CVE-2026-9"] },
    { id: "OSV-2026-1", aliases: ["CVE-2026-9"] },
    { id: "GHSA-9999-8888-7777", aliases: ["CVE-2020-1"], withdrawn: true },
  ]);
  assert.equal(groups.length, 1);
  assert.deepEqual(
    groups[0].map((rec) => rec.id).sort(),
    ["GHSA-1111-2222-3333", "OSV-2026-1"],
  );
});

test("a lockfile names the direct package and ignores project entries", () => {
  const collected = collectLockfileData({
    version: 1,
    dependencies: {
      "net8.0": {
        "App.Lib": {
          type: "Direct",
          requested: "[1.0.0, )",
          resolved: "1.0.0",
          dependencies: { "Newtonsoft.Json": "13.0.1" },
        },
        "Newtonsoft.Json": {
          type: "Transitive",
          resolved: "13.0.1",
          dependencies: { "System.Memory": "4.5.5" },
        },
        "System.Memory": { type: "Transitive", resolved: "4.5.5" },
        "App.Tests": { type: "Project" },
        "Pinned.Json": { type: "CentralTransitive", resolved: "8.0.4" },
      },
    },
  });
  const json = collected.installs.get("newtonsoft.json@13.0.1");
  const location = locationFor(json, collected);
  assert.equal(location.direct, false);
  assert.deepEqual(location.introducedBy, ["App.Lib"]);
  assert.deepEqual(introducedBy("System.Memory", "4.5.5", collected.parents, collected.direct), ["App.Lib"]);
  assert.equal(collected.installs.has("pinned.json@8.0.4"), true);
  assert.equal(collected.installs.get("pinned.json@8.0.4").direct, false);
  assert.equal([...collected.installs.values()].some((row) => row.name === "App.Tests"), false);
});

test("version 3 lockfiles read targets from the root", () => {
  const collected = collectLockfileData({
    version: 3,
    net8: {
      framework: "net8.0",
      dependencies: {
        "PackageA": { type: "Direct", resolved: "1.0.0" },
      },
    },
    "net8/linux-x64": {
      framework: "net8.0",
      dependencies: {
        "PackageB": { type: "Transitive", resolved: "2.0.0" },
      },
    },
  });
  assert.equal(collected.installs.get("packagea@1.0.0").direct, true);
  assert.equal(collected.installs.get("packageb@2.0.0").direct, false);
});

test("an edge attaches only to the resolved version it names", () => {
  const collected = collectLockfileData({
    version: 2,
    dependencies: {
      "net8.0": {
        App: { type: "Direct", resolved: "1.0.0", dependencies: { B: "1.0.0" } },
        B: { type: "Transitive", resolved: "1.0.0" },
      },
      "net48": {
        B: { type: "Transitive", resolved: "2.0.0" },
      },
    },
  });
  const first = locationFor(collected.installs.get("b@1.0.0"), collected);
  const second = locationFor(collected.installs.get("b@2.0.0"), collected);
  assert.deepEqual(first.introducedBy, ["App"]);
  assert.deepEqual(second.introducedBy, []);
});

test("central package versions supply direct pins and skip ranges and comments", () => {
  const collected = collectProjectRefs(
    `<Project>
      <ItemGroup>
        <PackageReference Include="Newtonsoft.Json" />
        <PackageReference Include="Range.Pkg" />
        <PackageReference Include="$(Computed)" />
        <PackageReference Remove="Nerdbank.GitVersioning" />
      </ItemGroup>
    </Project>`,
    `<Project>
      <ItemGroup>
        <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
        <PackageVersion Include="Range.Pkg" Version="1.*" />
        <PackageVersion Include="Antlr3.Runtime" Version="3.5.1" />
        <!-- <PackageVersion Include="Dahomey.Json" Version="1.12.2" /> -->
        <GlobalPackageReference Include="Nerdbank.GitVersioning" Version="3.6.133" />
      </ItemGroup>
    </Project>`,
    "src/App/App.csproj",
  );
  assert.equal(collected.installs.get("newtonsoft.json@13.0.3").production, true);
  assert.equal(collected.installs.has("nerdbank.gitversioning@3.6.133"), false);
  assert.equal(collected.installs.has("antlr3.runtime@3.5.1"), false);
  assert.equal(collected.installs.has("dahomey.json@1.12.2"), false);
  assert.equal(collected.warnings.some((warning) => warning.includes("Range.Pkg")), true);
  assert.equal(collected.warnings.some((warning) => warning.includes("$(Computed)")), true);
});

test("IsTestProject, the test sdk, and a Tests suffix mark a test project", () => {
  assert.equal(projectIsTest("src/App/App.csproj", "<Project><IsTestProject>true</IsTestProject></Project>"), true);
  assert.equal(projectIsTest("src/App.Tests/App.Tests.csproj", "<Project></Project>"), true);
  assert.equal(projectIsTest("src/App.UnitTests/App.UnitTests.csproj", "<Project></Project>"), true);
  assert.equal(
    projectIsTest("src/Sample/Sample.csproj", `<Project><PackageReference Include="xunit" Version="2.9.0" /></Project>`),
    true,
  );
  assert.equal(projectIsTest("src/App/App.csproj", "<Project></Project>"), false);
  assert.equal(projectIsTest("src/App/Fastest.csproj", "<Project></Project>"), false);
  assert.equal(projectIsTest("src/App/Latest.csproj", "<Project></Project>"), false);
  assert.equal(
    projectIsTest(
      "src/App/App.csproj",
      `<Project><PackageReference Include="Microsoft.Testing.Platform" /></Project>`,
    ),
    false,
  );
});

test("a bracketed version and a single property are exact", () => {
  assert.equal(exactNuGetVersion("[1.2.3]"), "1.2.3");
  assert.equal(exactNuGetVersion("[1.2.3, 1.2.3]"), "1.2.3");
  assert.equal(exactNuGetVersion("[1.0.0,2.0.0)"), null);
  assert.equal(exactNuGetVersion("1.2.*"), null);
  const collected = collectProjectRefs(
    `<Project>
      <PropertyGroup><JsonVersion>13.0.3</JsonVersion></PropertyGroup>
      <ItemGroup>
        <PackageReference Include="Newtonsoft.Json" Version="$(JsonVersion)" />
        <PackageReference Include="Dapper" Version="[2.1.28]" />
      </ItemGroup>
    </Project>`,
    `<Project><ItemGroup><PackageVersion Include="Unused.Pin" Version="$(Missing)" /></ItemGroup></Project>`,
    "App.csproj",
    {
      buildPropsXml: `<Project><ItemGroup><PackageReference Include="StyleCop.Analyzers" Version="1.1.118" /></ItemGroup></Project>`,
    },
  );
  assert.equal(collected.installs.has("newtonsoft.json@13.0.3"), true);
  assert.equal(collected.installs.has("dapper@2.1.28"), true);
  assert.equal(collected.installs.has("stylecop.analyzers@1.1.118"), true);
});

test("project.assets.json keeps the restored graph and skips project entries", () => {
  const collected = collectAssetsData({
    version: 3,
    targets: {
      "net8.0": {
        "Newtonsoft.Json/13.0.3": {
          type: "package",
          dependencies: { "System.Memory": "[4.5.5, )" },
        },
        "System.Memory/4.5.5": { type: "package" },
        "App/1.0.0": { type: "project" },
      },
    },
    project: {
      frameworks: {
        "net8.0": {
          dependencies: { "Newtonsoft.Json": { target: "Package", version: "[13.0.3, )" } },
        },
      },
    },
  });
  assert.equal(locationFor(collected.installs.get("newtonsoft.json@13.0.3"), collected).direct, true);
  assert.deepEqual(locationFor(collected.installs.get("system.memory@4.5.5"), collected).introducedBy, [
    "Newtonsoft.Json",
  ]);
  assert.equal([...collected.installs.values()].some((row) => row.name === "App"), false);
});

test("walk finds a lockfile under src and skips obj, bin, and symlinks", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "osv-nuget-scan-"));
  fs.mkdirSync(path.join(root, "src"));
  fs.mkdirSync(path.join(root, "obj", "app"), { recursive: true });
  fs.mkdirSync(path.join(root, "bin"));
  fs.writeFileSync(path.join(root, "src", "packages.lock.json"), "{}");
  fs.writeFileSync(path.join(root, "obj", "app", "packages.lock.json"), "{}");
  fs.writeFileSync(path.join(root, "bin", "packages.config"), "<packages />");
  fs.symlinkSync(path.join(root, "src"), path.join(root, "linked"));
  const found = { lockfiles: [], configs: [], projects: [] };
  walkFiles(root, root, found, []);
  assert.deepEqual(found.lockfiles, ["src/packages.lock.json"]);
  assert.deepEqual(found.configs, []);
  fs.rmSync(root, { recursive: true, force: true });
});

test("a lockfile wins over a direct pin in the same directory", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "osv-nuget-scan-"));
  try {
    fs.writeFileSync(
      path.join(root, "Directory.Packages.props"),
      `<Project><ItemGroup>
        <PackageVersion Include="Dapper" Version="2.0.0" />
        <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
        <PackageVersion Include="Antlr3.Runtime" Version="3.5.1" />
      </ItemGroup></Project>`,
    );
    fs.mkdirSync(path.join(root, "src", "Locked"), { recursive: true });
    fs.mkdirSync(path.join(root, "src", "App.Tests"), { recursive: true });
    fs.writeFileSync(
      path.join(root, "src", "Locked", "Locked.csproj"),
      `<Project><ItemGroup><PackageReference Include="Dapper" /></ItemGroup></Project>`,
    );
    fs.writeFileSync(
      path.join(root, "src", "Locked", "packages.lock.json"),
      JSON.stringify({
        version: 1,
        dependencies: { "net8.0": { Dapper: { type: "Direct", resolved: "9.9.9" } } },
      }),
    );
    fs.writeFileSync(
      path.join(root, "src", "App.Tests", "App.Tests.csproj"),
      `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" /></ItemGroup></Project>`,
    );
    fs.mkdirSync(path.join(root, "obj"));
    fs.writeFileSync(path.join(root, "obj", "packages.lock.json"), "{\"version\":1,\"dependencies\":{}}");
    const scanned = scanTree(root);
    const names = scanned.packages.map((pkg) => `${pkg.name}@${pkg.version}`);
    assert.deepEqual(names, ["Dapper@9.9.9", "Newtonsoft.Json@13.0.3"]);
    const dapper = scanned.packages.find((pkg) => pkg.name === "Dapper");
    assert.equal(dapper.locations[0].lockfile, "src/Locked/packages.lock.json");
    assert.equal(dapper.locations[0].directProduction, true);
    const json = scanned.packages.find((pkg) => pkg.name === "Newtonsoft.Json");
    assert.equal(json.locations[0].production, false);
    assert.equal(json.locations[0].direct, true);
    assert.match(scanned.warnings[0], /transitive NuGet dependencies were not queried/);
    assert.match(scanned.warnings.join("\n"), /1 package version pinned/);
    assert.equal(scanned.warnings.some((warning) => warning.includes("obj/")), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("central versions above the scan root and a chained Directory.Build.props are visible", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "osv-nuget-scan-"));
  try {
    fs.writeFileSync(
      path.join(parent, "Directory.Packages.props"),
      `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`,
    );
    fs.writeFileSync(
      path.join(parent, "Directory.Build.props"),
      `<Project><ItemGroup><PackageReference Include="Parent.Pkg" Version="1.0.0" /></ItemGroup></Project>`,
    );
    const root = path.join(parent, "app");
    fs.mkdirSync(path.join(root, "plain"), { recursive: true });
    fs.mkdirSync(path.join(root, "chained"), { recursive: true });
    fs.writeFileSync(
      path.join(root, "plain", "Directory.Build.props"),
      `<Project><ItemGroup><PackageReference Include="Child.Pkg" Version="2.0.0" /></ItemGroup></Project>`,
    );
    fs.writeFileSync(
      path.join(root, "plain", "Plain.csproj"),
      `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" /></ItemGroup></Project>`,
    );
    fs.writeFileSync(
      path.join(root, "chained", "Directory.Build.props"),
      `<Project>
        <Import Project="$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../'))" />
        <ItemGroup><PackageReference Include="Child.Pkg" Version="2.0.0" /></ItemGroup>
      </Project>`,
    );
    fs.writeFileSync(path.join(root, "chained", "Chained.csproj"), "<Project></Project>");
    const scanned = scanTree(root);
    const names = scanned.packages.map((pkg) => `${pkg.name}@${pkg.version}`).sort();
    assert.deepEqual(names, ["Child.Pkg@2.0.0", "Newtonsoft.Json@13.0.3", "Parent.Pkg@1.0.0"]);
    const parentPkg = scanned.packages.find((pkg) => pkg.name === "Parent.Pkg");
    assert.deepEqual(parentPkg.locations.map((loc) => loc.lockfile), ["chained/Chained.csproj"]);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("project.assets.json wins over a direct pin, and a lockfile wins over both", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "osv-nuget-scan-"));
  try {
    const app = path.join(root, "App");
    const locked = path.join(root, "Locked");
    fs.mkdirSync(path.join(app, "obj"), { recursive: true });
    fs.mkdirSync(path.join(locked, "obj"), { recursive: true });
    const appProject = path.join(app, "App.csproj");
    fs.writeFileSync(
      appProject,
      `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="1.0.0" /></ItemGroup></Project>`,
    );
    fs.writeFileSync(
      path.join(app, "obj", "project.assets.json"),
      JSON.stringify({
        version: 3,
        targets: {
          "net8.0": {
            "Newtonsoft.Json/13.0.3": { type: "package", dependencies: { "System.Memory": "4.5.5" } },
            "System.Memory/4.5.5": { type: "package" },
          },
        },
        project: {
          restore: { projectUniqueName: appProject },
          frameworks: {
            "net8.0": { dependencies: { "Newtonsoft.Json": { target: "Package", version: "[13.0.3, )" } } },
          },
        },
      }),
    );
    const past = new Date(Date.now() - 60_000);
    fs.utimesSync(path.join(app, "obj", "project.assets.json"), past, past);
    fs.writeFileSync(
      path.join(locked, "Locked.csproj"),
      `<Project><ItemGroup><PackageReference Include="Dapper" Version="1.0.0" /></ItemGroup></Project>`,
    );
    fs.writeFileSync(
      path.join(locked, "packages.lock.json"),
      JSON.stringify({ version: 1, dependencies: { "net8.0": { Dapper: { type: "Direct", resolved: "9.9.9" } } } }),
    );
    fs.writeFileSync(
      path.join(locked, "obj", "project.assets.json"),
      JSON.stringify({
        version: 3,
        targets: { "net8.0": { "Dapper/1.2.3": { type: "package" } } },
        project: { restore: { projectUniqueName: path.join(locked, "Locked.csproj") }, frameworks: {} },
      }),
    );
    const scanned = scanTree(root);
    const names = scanned.packages.map((pkg) => `${pkg.name}@${pkg.version}`).sort();
    assert.deepEqual(names, ["Dapper@9.9.9", "Newtonsoft.Json@13.0.3", "System.Memory@4.5.5"]);
    const memory = scanned.packages.find((pkg) => pkg.name === "System.Memory");
    assert.deepEqual(memory.locations[0].introducedBy, ["Newtonsoft.Json"]);
    assert.equal(memory.locations[0].lockfile, "App/obj/project.assets.json");
    assert.match(scanned.warnings.join("\n"), /older than App\/App.csproj/);
    assert.equal(scanned.warnings.some((warning) => /transitive NuGet dependencies were not queried/.test(warning)), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
