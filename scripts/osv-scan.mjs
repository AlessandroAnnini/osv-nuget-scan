#!/usr/bin/env node
// Match NuGet package versions against https://api.osv.dev.
// Stdout is one JSON document. Progress goes to stderr. No dependencies.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ECOSYSTEM = "NuGet";
const API = "https://api.osv.dev/v1";
const BATCH = 800;
const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
const SKIP_DIRS = new Set([".git", "bin", "obj", "node_modules"]);
const DOTNET_INDEX =
  "https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json";
// Shared framework name in `dotnet --list-runtimes` -> its version field in releases.json.
const RUNTIME_COMPONENTS = {
  "Microsoft.NETCore.App": "runtime",
  "Microsoft.AspNetCore.App": "aspnetcore-runtime",
  "Microsoft.WindowsDesktop.App": "windowsdesktop",
};
const TEST_PACKAGES = new Set([
  "microsoft.net.test.sdk",
  "mstest.testframework",
  "mstest.testadapter",
  "xunit",
  "xunit.runner.visualstudio",
  "nunit",
  "nunit3testadapter",
  "tunit",
]);
const TEST_PROJECT_NAME =
  /(?:^|\/)(?:[^/]+\.)?(?:Unit|Integration|Functional|EndToEnd|E2E)?Tests?\.csproj$/i;
const NUGET_VERSION =
  /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function fail(error) {
  process.stdout.write(JSON.stringify({ ecosystem: ECOSYSTEM, error }, null, 2) + "\n");
  process.exit(1);
}

function relPath(root, full) {
  const rel = path.relative(root, full);
  return rel.split(path.sep).join("/");
}

function dirName(rel) {
  const index = rel.lastIndexOf("/");
  return index === -1 ? "" : rel.slice(0, index);
}

export function stripXmlComments(xml) {
  return String(xml).replace(/^\uFEFF/, "").replace(/<!--[\s\S]*?-->/g, "");
}

function attributes(source) {
  const out = {};
  const re = /([A-Za-z_][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let match;
  while ((match = re.exec(source))) out[match[1]] = match[2] ?? match[3] ?? "";
  return out;
}

function elements(xml, tag) {
  const re = new RegExp(`<${tag}\\b([^>]*?)(?:/>|>([\\s\\S]*?)</${tag}\\s*>)`, "gi");
  const found = [];
  let match;
  while ((match = re.exec(xml))) {
    found.push({ attrs: attributes(match[1]), inner: match[2] ?? "" });
  }
  return found;
}

function childText(inner, tag) {
  const match = inner.match(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}\\s*>`, "i"));
  return match ? match[1].trim() : "";
}

export function parseNuGet(value) {
  const match = String(value).trim().match(NUGET_VERSION);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2] ?? 0),
    patch: Number(match[3] ?? 0),
    revision: Number(match[4] ?? 0),
    pre: match[5] ? match[5].split(".") : null,
  };
}

function compareLabel(left, right) {
  const leftNum = /^\d+$/.test(left);
  const rightNum = /^\d+$/.test(right);
  if (leftNum && rightNum && Number(left) !== Number(right)) return Number(left) - Number(right);
  if (leftNum !== rightNum) return leftNum ? -1 : 1;
  const a = left.toLowerCase();
  const b = right.toLowerCase();
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

// Null when either side is not a NuGet version. Callers must not treat that as an order.
export function compareVersions(a, b) {
  const pa = parseNuGet(a);
  const pb = parseNuGet(b);
  if (!pa || !pb) return null;
  if (pa.major !== pb.major) return pa.major - pb.major;
  if (pa.minor !== pb.minor) return pa.minor - pb.minor;
  if (pa.patch !== pb.patch) return pa.patch - pb.patch;
  if (pa.revision !== pb.revision) return pa.revision - pb.revision;
  if (!pa.pre && !pb.pre) return 0;
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  const length = Math.max(pa.pre.length, pb.pre.length);
  for (let i = 0; i < length; i += 1) {
    const x = pa.pre[i];
    const y = pb.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const cmp = compareLabel(x, y);
    if (cmp !== 0) return cmp;
  }
  return 0;
}

export function walkFiles(dir, root, found, warnings) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    const message = `cannot read ${relPath(root, dir) || dir}: ${err.message}`;
    if (dir === root) {
      const error = new Error(message);
      error.scanError = true;
      throw error;
    }
    warnings.push(message);
    return;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(full, root, found, warnings);
      continue;
    }
    if (!entry.isFile()) continue;
    const name = entry.name.toLowerCase();
    const rel = relPath(root, full);
    if (name === "packages.lock.json") found.lockfiles.push(rel);
    else if (name === "packages.config") found.configs.push(rel);
    else if (name.endsWith(".csproj")) found.projects.push(rel);
  }
}

export function projectIsTest(rel, xml, extraXml = "") {
  if (TEST_PROJECT_NAME.test(rel)) return true;
  const text = `${stripXmlComments(xml)}\n${stripXmlComments(extraXml)}`;
  if (/<IsTestProject\b[^>]*>\s*true\s*<\/IsTestProject>/i.test(text)) return true;
  for (const tag of ["PackageReference", "GlobalPackageReference"]) {
    for (const el of elements(text, tag)) {
      const name = el.attrs.Include?.trim().toLowerCase();
      if (name && TEST_PACKAGES.has(name)) return true;
    }
  }
  return false;
}

export function readProperties(xml) {
  const props = new Map();
  for (const group of elements(stripXmlComments(xml || ""), "PropertyGroup")) {
    const re = /<([A-Za-z_][\w.-]*)\b[^>]*>([^<]*)<\/\1>/g;
    let match;
    while ((match = re.exec(group.inner))) props.set(match[1].toLowerCase(), match[2].trim());
  }
  return props;
}

export function resolveText(value, properties) {
  let text = String(value ?? "").trim();
  for (let i = 0; i < 8; i += 1) {
    const match = text.match(/^\$\(([^)]+)\)$/);
    if (!match) return text;
    const next = properties.get(match[1].trim().toLowerCase());
    if (next === undefined) return text;
    text = next.trim();
  }
  return text;
}

// A bare version, [1.2.3], or [1.2.3, 1.2.3]. Ranges and floating versions return null.
export function exactNuGetVersion(spec) {
  const text = String(spec ?? "").trim();
  if (!text) return null;
  if (parseNuGet(text)) return text;
  if (!text.includes(",")) {
    const single = text.match(/^\[(.+)\]$/);
    if (single && parseNuGet(single[1].trim())) return single[1].trim();
  }
  const pair = text.match(/^\[([^,\]]+)\s*,\s*([^,\]]+)\]$/);
  if (pair && pair[1].trim() === pair[2].trim() && parseNuGet(pair[1].trim())) return pair[1].trim();
  return null;
}

export function packageVersions(xml, properties = new Map()) {
  const local = new Map(properties);
  for (const [key, value] of readProperties(xml)) local.set(key, value);
  const found = [];
  for (const el of elements(stripXmlComments(xml), "PackageVersion")) {
    const name = resolveText(el.attrs.Include || "", local);
    const version = resolveText(el.attrs.Version || childText(el.inner, "Version") || "", local);
    if (!name || !version || name.includes("$")) continue;
    found.push({ name, version });
  }
  return found;
}

function ownVersion(el) {
  return (
    el.attrs.VersionOverride ||
    childText(el.inner, "VersionOverride") ||
    el.attrs.Version ||
    childText(el.inner, "Version") ||
    ""
  ).trim();
}

export function introducedBy(name, version, parents, direct) {
  const directLower = new Set([...direct].map((item) => item.toLowerCase()));
  const found = new Set();
  const seen = new Set([`${name.toLowerCase()}@${version}`]);
  const queue = [{ name, version }];
  while (queue.length) {
    const current = queue.shift();
    const key = `${current.name.toLowerCase()}@${current.version}`;
    for (const encoded of parents.get(key) || []) {
      const split = encoded.indexOf("\0");
      const parent = { name: encoded.slice(0, split), version: encoded.slice(split + 1) };
      if (directLower.has(parent.name.toLowerCase())) {
        found.add(parent.name);
        continue;
      }
      const parentKey = `${parent.name.toLowerCase()}@${parent.version}`;
      if (!seen.has(parentKey)) {
        seen.add(parentKey);
        queue.push(parent);
      }
    }
  }
  return [...found].sort((a, b) => a.localeCompare(b));
}

export function locationFor(row, item) {
  const direct = row.direct;
  return {
    lockfile: item.rel,
    production: row.production,
    direct,
    directProduction: direct && row.production,
    introducedBy: direct ? [] : introducedBy(row.name, row.version, item.parents, item.direct),
  };
}

function addParent(parents, childName, childVersion, parentName, parentVersion) {
  if (childName.toLowerCase() === parentName.toLowerCase() && childVersion === parentVersion) return;
  const key = `${childName.toLowerCase()}@${childVersion}`;
  if (!parents.has(key)) parents.set(key, new Set());
  parents.get(key).add(`${parentName}\0${parentVersion}`);
}

function dependencyVersion(value) {
  if (typeof value === "string") return value.trim();
  if (value && typeof value === "object" && typeof value.version === "string") return value.version.trim();
  return "";
}

// Version 1 and 2 keep targets under dependencies. Version 3 puts each target at the root.
export function lockTargets(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  const version = Number(data.version);
  if (version >= 3) {
    const targets = [];
    for (const [key, value] of Object.entries(data)) {
      if (key === "version") continue;
      if (!value || typeof value !== "object" || Array.isArray(value)) continue;
      if (!value.dependencies || typeof value.dependencies !== "object") continue;
      targets.push(value.dependencies);
    }
    return targets;
  }
  if (!data.dependencies || typeof data.dependencies !== "object" || Array.isArray(data.dependencies)) {
    return null;
  }
  return Object.values(data.dependencies).filter(
    (value) => value && typeof value === "object" && !Array.isArray(value),
  );
}

function recordTarget(packages, installs, direct, parents, testProject) {
  const resolved = new Map();
  for (const [name, meta] of Object.entries(packages)) {
    if (!meta || typeof meta !== "object" || Array.isArray(meta)) continue;
    const type = String(meta.type ?? "");
    if (type.toLowerCase() === "project") continue;
    if (typeof meta.resolved !== "string" || !parseNuGet(meta.resolved)) continue;
    const key = `${name.toLowerCase()}@${meta.resolved}`;
    let row = installs.get(key);
    if (!row) {
      row = { name, version: meta.resolved, direct: false, production: !testProject };
      installs.set(key, row);
    }
    if (type.toLowerCase() === "direct") {
      row.direct = true;
      direct.add(row.name);
    }
    const list = resolved.get(name.toLowerCase()) ?? [];
    list.push({ name: row.name, version: meta.resolved, dependencies: meta.dependencies ?? {} });
    resolved.set(name.toLowerCase(), list);
  }
  for (const list of resolved.values()) {
    for (const pkg of list) {
      if (!pkg.dependencies || typeof pkg.dependencies !== "object") continue;
      for (const [depName, depValue] of Object.entries(pkg.dependencies)) {
        const version = dependencyVersion(depValue);
        const candidates = resolved.get(depName.toLowerCase()) ?? [];
        const parsed = version ? parseNuGet(version) : null;
        const matched = parsed
          ? candidates.filter((candidate) => compareVersions(candidate.version, version) === 0)
          : [];
        // One resolved version in this target is the version NuGet selected, even when the edge names a range.
        const chosen = matched.length ? matched : candidates.length === 1 ? candidates : [];
        for (const child of chosen) addParent(parents, child.name, child.version, pkg.name, pkg.version);
      }
    }
  }
}

export function collectLockfileData(data, rel = "packages.lock.json", options = {}) {
  const targets = lockTargets(data);
  if (!targets) return { error: `${rel}: not a NuGet packages.lock.json (missing dependencies)` };
  const testProject = Boolean(options.testProject);
  const installs = new Map();
  const direct = new Set();
  const parents = new Map();
  for (const packages of targets) recordTarget(packages, installs, direct, parents, testProject);
  return { rel, kind: "lock", testProject, installs, direct, parents, warnings: [] };
}

function addDirect(installs, direct, name, version, testProject) {
  const key = `${name.toLowerCase()}@${version}`;
  if (installs.has(key)) return;
  installs.set(key, { name, version, direct: true, production: !testProject });
  direct.add(name);
}

export function collectPackagesConfig(xml, rel = "packages.config", options = {}) {
  const testProject = Boolean(options.testProject);
  const warnings = [];
  const installs = new Map();
  const direct = new Set();
  for (const el of elements(stripXmlComments(xml), "package")) {
    const name = el.attrs.id;
    const version = (el.attrs.version || "").trim();
    if (!name || !version) continue;
    const exact = exactNuGetVersion(version);
    if (!exact) {
      warnings.push(`${rel}: ${name} version '${version}' is not an exact NuGet version`);
      continue;
    }
    addDirect(installs, direct, name, exact, testProject);
  }
  return { rel, kind: "config", testProject, installs, direct, parents: new Map(), warnings };
}

function dropPackage(installs, direct, name) {
  const key = name.toLowerCase();
  for (const id of [...installs.keys()]) {
    if (id.startsWith(`${key}@`)) installs.delete(id);
  }
  for (const item of [...direct]) {
    if (item.toLowerCase() === key) direct.delete(item);
  }
}

function takeRef(el, label, rel, testProject, versions, properties, installs, direct, warnings) {
  if (el.attrs.Remove !== undefined && el.attrs.Include === undefined) {
    const name = resolveText(el.attrs.Remove, properties);
    if (name && !name.includes("$")) dropPackage(installs, direct, name);
    return;
  }
  const rawName = el.attrs.Include || "";
  const name = resolveText(rawName, properties);
  if (!name) return;
  if (name.includes("$") || name.includes("%")) {
    warnings.push(`${rel}: skipped ${label} '${rawName}' because the name is not a package id`);
    return;
  }
  const pinned = versions.get(name.toLowerCase());
  const rawVersion = resolveText(ownVersion(el) || pinned?.version || "", properties);
  const version = exactNuGetVersion(rawVersion);
  if (!version) {
    warnings.push(
      rawVersion
        ? `${rel}: ${name} version '${rawVersion}' is not an exact NuGet version`
        : `${rel}: ${name} has no version`,
    );
    return;
  }
  addDirect(installs, direct, name, version, testProject);
}

function applyRefs(xml, label, rel, testProject, versions, properties, installs, direct, warnings) {
  const stripped = stripXmlComments(xml || "");
  for (const el of elements(stripped, "PackageReference")) {
    takeRef(el, label, rel, testProject, versions, properties, installs, direct, warnings);
  }
  for (const el of elements(stripped, "GlobalPackageReference")) {
    takeRef(el, "GlobalPackageReference", rel, testProject, versions, properties, installs, direct, warnings);
  }
}

export function collectProjectRefs(projectXml, centralXml, rel, options = {}) {
  const testProject = Boolean(options.testProject);
  const buildXml = options.buildPropsXml || "";
  const warnings = [];
  const buildProps = readProperties(buildXml);
  const centralProps = new Map(buildProps);
  for (const [key, value] of readProperties(centralXml)) centralProps.set(key, value);
  const projectProps = new Map(centralProps);
  for (const [key, value] of readProperties(projectXml)) projectProps.set(key, value);
  const versions = new Map(
    packageVersions(centralXml, centralProps).map((pin) => [pin.name.toLowerCase(), pin]),
  );
  const installs = new Map();
  const direct = new Set();
  applyRefs(buildXml, "PackageReference", rel, testProject, versions, buildProps, installs, direct, warnings);
  applyRefs(centralXml, "PackageReference", rel, testProject, versions, centralProps, installs, direct, warnings);
  applyRefs(projectXml, "PackageReference", rel, testProject, versions, projectProps, installs, direct, warnings);
  return { rel, kind: "project", testProject, installs, direct, parents: new Map(), warnings };
}

export function collectAssetsData(data, rel = "obj/project.assets.json", options = {}) {
  const targets = data?.targets;
  if (!targets || typeof targets !== "object" || Array.isArray(targets)) {
    return { error: `${rel}: not a project.assets.json (missing targets)` };
  }
  const directNames = new Set();
  for (const framework of Object.values(data.project?.frameworks ?? {})) {
    if (!framework || typeof framework !== "object") continue;
    for (const [name, meta] of Object.entries(framework.dependencies ?? {})) {
      if (typeof meta === "string") {
        directNames.add(name.toLowerCase());
        continue;
      }
      if (String(meta?.target ?? "Package").toLowerCase() === "package") directNames.add(name.toLowerCase());
    }
  }
  const groups = [];
  for (const libraries of Object.values(targets)) {
    if (!libraries || typeof libraries !== "object" || Array.isArray(libraries)) continue;
    const packages = {};
    for (const [identity, meta] of Object.entries(libraries)) {
      if (!meta || typeof meta !== "object") continue;
      if (String(meta.type ?? "package").toLowerCase() !== "package") continue;
      const slash = identity.lastIndexOf("/");
      if (slash <= 0) continue;
      const name = identity.slice(0, slash);
      const version = identity.slice(slash + 1);
      if (!parseNuGet(version)) continue;
      packages[name] = {
        type: directNames.has(name.toLowerCase()) ? "Direct" : "Transitive",
        resolved: version,
        dependencies: meta.dependencies ?? {},
      };
    }
    groups.push(packages);
  }
  const testProject = Boolean(options.testProject);
  const installs = new Map();
  const direct = new Set();
  const parents = new Map();
  for (const packages of groups) recordTarget(packages, installs, direct, parents, testProject);
  return { rel, kind: "assets", testProject, installs, direct, parents, warnings: [] };
}

function readText(file) {
  return fs.readFileSync(file, "utf8").replace(/^\uFEFF/, "");
}

function findFileAbove(startDir, fileName) {
  let dir = startDir;
  const stop = path.parse(dir).root;
  while (true) {
    const candidate = path.join(dir, fileName);
    try {
      if (fs.lstatSync(candidate).isFile()) return candidate;
    } catch {
      // The file is not in this directory.
    }
    if (dir === stop) return null;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

// Nearest file wins, matching MSBuild GetPathOfFileAbove. A file that imports the same name also contributes its parent.
function importedPropsFiles(startDir, fileName, read) {
  const found = [];
  const seen = new Set();
  let dir = startDir;
  while (found.length < 8) {
    const file = findFileAbove(dir, fileName);
    if (!file || seen.has(file)) break;
    seen.add(file);
    let xml;
    try {
      xml = read(file);
    } catch (err) {
      return { files: found.reverse(), error: `${file}: ${err.message}` };
    }
    found.push({ file, xml });
    const importsParent = new RegExp(`<Import\\b[^>]*${fileName.replace(/\./g, "\\.")}`, "i").test(
      stripXmlComments(xml),
    );
    if (!importsParent) break;
    const parent = path.dirname(path.dirname(file));
    if (parent === path.dirname(file)) break;
    dir = parent;
  }
  return { files: found.reverse() };
}

function coverageWarning(items) {
  const partial = items.filter(
    (item) => (item.kind === "project" || item.kind === "config") && item.installs.size,
  );
  if (!partial.length) return null;
  const files = partial.map((item) => item.rel).sort().join(", ");
  return `only exact direct versions were queried for ${files}, so transitive NuGet dependencies were not queried`;
}

function unusedPinWarning(count) {
  if (!count) return null;
  const noun = count === 1 ? "package version" : "package versions";
  const verb = count === 1 ? "is" : "are";
  const queried = count === 1 ? "was" : "were";
  return `${count} ${noun} pinned in Directory.Packages.props ${verb} not referenced by a project under the scan root and ${queried} not queried`;
}

function assetsPath(projectDir, xml) {
  const props = readProperties(xml);
  const configured = props.get("intermediateoutputpath") || props.get("baseintermediateoutputpath");
  let dir = path.join(projectDir, "obj");
  if (configured && !configured.includes("$") && !configured.includes("%")) dir = path.resolve(projectDir, configured);
  return path.join(dir, "project.assets.json");
}

function useAssetsFile(root, rel, xml, siblingCount, testProject, warnings, items) {
  const projectAbs = path.join(root, rel);
  const assetsAbs = assetsPath(path.dirname(projectAbs), xml);
  let stat;
  try {
    stat = fs.lstatSync(assetsAbs);
  } catch {
    return false;
  }
  if (!stat.isFile()) return false;
  const assetsRel = relPath(root, assetsAbs);
  let data;
  try {
    data = JSON.parse(readText(assetsAbs));
  } catch (err) {
    warnings.push(`${assetsRel}: ${err.message}`);
    return false;
  }
  const unique = data?.project?.restore?.projectUniqueName;
  const belongs =
    typeof unique === "string" && unique.trim()
      ? path.resolve(unique) === path.resolve(projectAbs)
      : siblingCount === 1;
  if (!belongs) {
    warnings.push(`${assetsRel}: restore project is ${unique || "unspecified"}, not ${rel}`);
    return false;
  }
  const collected = collectAssetsData(data, assetsRel, { testProject });
  if (collected.error) {
    warnings.push(collected.error);
    return false;
  }
  if (fs.statSync(projectAbs).mtimeMs > stat.mtimeMs + 1000) {
    warnings.push(`${assetsRel}: older than ${rel}; resolved versions may be stale`);
  }
  warnings.push(...collected.warnings);
  if (collected.installs.size) items.push(collected);
  else warnings.push(`${assetsRel}: no resolved packages`);
  return true;
}

function remember(byKey, row, item) {
  const key = `${row.name.toLowerCase()}@${row.version}`;
  let entry = byKey.get(key);
  if (!entry) {
    entry = { name: row.name, version: row.version, locations: [] };
    byKey.set(key, entry);
  }
  entry.locations.push(locationFor(row, item));
}

export function scanTree(rootInput) {
  const root = path.resolve(rootInput);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    return { error: `not a directory: ${root}` };
  }
  const found = { lockfiles: [], configs: [], projects: [] };
  const warnings = [];
  try {
    walkFiles(root, root, found, warnings);
  } catch (err) {
    if (err.scanError) return { error: err.message };
    throw err;
  }

  const projectXml = new Map();
  for (const rel of found.projects) {
    try {
      projectXml.set(rel, readText(path.join(root, rel)));
    } catch (err) {
      warnings.push(`${rel}: ${err.message}`);
    }
  }

  const textCache = new Map();
  const cachedText = (file) => {
    if (textCache.has(file)) {
      const hit = textCache.get(file);
      if (hit instanceof Error) throw hit;
      return hit;
    }
    try {
      const text = readText(file);
      textCache.set(file, text);
      return text;
    } catch (err) {
      textCache.set(file, err);
      throw err;
    }
  };
  const contextByDir = new Map();
  const contextFor = (projectRel) => {
    const dir = path.dirname(path.join(root, projectRel));
    if (contextByDir.has(dir)) return contextByDir.get(dir);
    const build = importedPropsFiles(dir, "Directory.Build.props", cachedText);
    const central = importedPropsFiles(dir, "Directory.Packages.props", cachedText);
    if (build.error) warnings.push(build.error);
    if (central.error) warnings.push(central.error);
    const value = {
      buildXml: build.files.map((file) => file.xml).join("\n"),
      centralXml: central.files.map((file) => file.xml).join("\n"),
    };
    contextByDir.set(dir, value);
    return value;
  };
  const siblingsIn = (dir) => found.projects.filter((project) => dirName(project) === dir && projectXml.has(project));
  const directoryIsTest = (dir) => {
    const siblings = siblingsIn(dir);
    if (!siblings.length) return false;
    const { buildXml } = contextFor(siblings[0]);
    return siblings.every((project) => projectIsTest(project, projectXml.get(project), buildXml));
  };

  const lockedDirs = new Set();
  const configDirs = new Set();
  const items = [];

  for (const rel of found.lockfiles.sort()) {
    let data;
    try {
      data = JSON.parse(readText(path.join(root, rel)));
    } catch (err) {
      warnings.push(`${rel}: ${err.message}`);
      continue;
    }
    const collected = collectLockfileData(data, rel, { testProject: directoryIsTest(dirName(rel)) });
    if (collected.error) {
      warnings.push(collected.error);
      continue;
    }
    lockedDirs.add(dirName(rel));
    warnings.push(...collected.warnings);
    if (collected.installs.size) items.push(collected);
    else warnings.push(`${rel}: no resolved packages`);
  }

  for (const rel of found.configs.sort()) {
    if (lockedDirs.has(dirName(rel))) continue;
    let xml;
    try {
      xml = readText(path.join(root, rel));
    } catch (err) {
      warnings.push(`${rel}: ${err.message}`);
      continue;
    }
    configDirs.add(dirName(rel));
    const collected = collectPackagesConfig(xml, rel, { testProject: directoryIsTest(dirName(rel)) });
    warnings.push(...collected.warnings);
    if (collected.installs.size) items.push(collected);
  }

  const pinned = new Map();
  let usedProjectRefs = false;
  for (const rel of found.projects.sort()) {
    const dir = dirName(rel);
    if (lockedDirs.has(dir) || configDirs.has(dir)) continue;
    const xml = projectXml.get(rel);
    if (xml === undefined) continue;
    const context = contextFor(rel);
    const testProject = projectIsTest(rel, xml, context.buildXml);
    if (useAssetsFile(root, rel, xml, siblingsIn(dir).length, testProject, warnings, items)) continue;
    for (const pin of packageVersions(context.centralXml, readProperties(context.buildXml))) {
      pinned.set(pin.name.toLowerCase(), pin);
    }
    const collected = collectProjectRefs(xml, context.centralXml, rel, {
      testProject,
      buildPropsXml: context.buildXml,
    });
    warnings.push(...collected.warnings);
    if (collected.installs.size) {
      items.push(collected);
      usedProjectRefs = true;
    }
  }

  const targets = [];
  for (const rel of found.projects.sort()) {
    const xml = projectXml.get(rel);
    if (xml === undefined) continue;
    for (const target of targetFrameworks(xml, contextFor(rel).buildXml)) targets.push({ project: rel, ...target });
  }

  const byKey = new Map();
  for (const item of items) {
    for (const row of item.installs.values()) remember(byKey, row, item);
  }
  const packages = [...byKey.values()].sort(
    (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version),
  );
  for (const pkg of packages) pkg.locations.sort((a, b) => a.lockfile.localeCompare(b.lockfile));

  if (usedProjectRefs) {
    const queried = new Set(packages.map((pkg) => pkg.name.toLowerCase()));
    let unused = 0;
    for (const name of pinned.keys()) if (!queried.has(name)) unused += 1;
    const unusedWarning = unusedPinWarning(unused);
    if (unusedWarning) warnings.push(unusedWarning);
  }
  const coverage = coverageWarning(items);
  if (coverage) warnings.unshift(coverage);

  if (!packages.length) {
    const detail = warnings.length ? `: ${warnings.join("; ")}` : "";
    return { error: `no NuGet package versions found under ${root}${detail}` };
  }
  return {
    root,
    packages,
    warnings,
    lockfiles: [...new Set(items.filter((item) => item.installs.size).map((item) => item.rel))].sort(),
    targets,
  };
}

// TargetFramework and TargetFrameworks, from the project or Directory.Build.props.
// channel is the .NET release line, or null with a reason when it is not a .NET runtime.
export function targetFrameworks(xml, buildXml = "") {
  const properties = readProperties(`${buildXml}\n${xml}`);
  const raw = [properties.get("targetframeworks"), properties.get("targetframework")].find(
    (value) => value !== undefined && value !== "",
  );
  if (raw === undefined) return [];
  const out = [];
  for (const part of resolveText(raw, properties).split(";")) {
    const tfm = part.trim();
    if (!tfm) continue;
    const modern = tfm.match(/^net(\d+)\.(\d+)(?:-[A-Za-z0-9.]+)?$/i);
    const core = tfm.match(/^netcoreapp(\d+)\.(\d+)$/i);
    if (modern && Number(modern[1]) >= 5) out.push({ targetFramework: tfm, channel: `${modern[1]}.${modern[2]}` });
    else if (core) out.push({ targetFramework: tfm, channel: `${core[1]}.${core[2]}` });
    else if (/^net\d{2,3}$/i.test(tfm)) {
      out.push({ targetFramework: tfm, channel: null, reason: ".NET Framework is serviced through Windows Update and is not covered" });
    } else if (/^netstandard/i.test(tfm)) {
      out.push({ targetFramework: tfm, channel: null, reason: ".NET Standard is not a runtime" });
    } else {
      out.push({ targetFramework: tfm, channel: null, reason: "not a recognized .NET target framework" });
    }
  }
  return out;
}

// Lines of `dotnet --list-runtimes`, such as "Microsoft.NETCore.App 8.0.32 [/usr/lib/dotnet/...]".
export function parseListRuntimes(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    const match = line.trim().match(/^(Microsoft\.[A-Za-z.]+)\s+(\S+)\s+\[/);
    if (match && RUNTIME_COMPONENTS[match[1]]) out.push({ component: match[1], version: match[2] });
  }
  return out;
}

function installedRuntimes() {
  try {
    const text = execFileSync("dotnet", ["--list-runtimes"], {
      encoding: "utf8",
      timeout: 15000,
      stdio: ["ignore", "pipe", "ignore"],
      env: { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: "1", DOTNET_NOLOGO: "1" },
    });
    return parseListRuntimes(text);
  } catch {
    return null;
  }
}

function channelOf(version) {
  const parsed = parseNuGet(version);
  return parsed ? `${parsed.major}.${parsed.minor}` : null;
}

// Support phase and end of life for one release line from releases-index.json.
export function channelStatus(channel, index, now = new Date()) {
  const entry = (index?.["releases-index"] ?? []).find((item) => item["channel-version"] === channel);
  if (!entry) {
    return { releaseLine: channel, supportPhase: null, releaseType: null, endOfLife: null, endOfLifeDate: null };
  }
  const end = entry["eol-date"] || null;
  return {
    releaseLine: channel,
    supportPhase: entry["support-phase"] ?? null,
    releaseType: entry["release-type"] ?? null,
    endOfLife: entry["support-phase"] === "eol" || (end ? new Date(`${end}T23:59:59Z`) < now : false),
    endOfLifeDate: end,
  };
}

export function latestLts(index) {
  const lines = (index?.["releases-index"] ?? [])
    .filter((item) => item["release-type"] === "lts" && item["support-phase"] === "active")
    .map((item) => item["channel-version"])
    .sort((a, b) => compareVersions(a, b) ?? 0);
  return lines.at(-1) ?? null;
}

// One installed shared framework against its line's releases.json. cve-list belongs to a whole
// release, so the CVEs are the ones fixed in releases newer than this version, not per component.
export function checkDotnetRuntime(component, version, index, releases, now = new Date()) {
  const field = RUNTIME_COMPONENTS[component];
  const status = channelStatus(channelOf(version), index, now);
  const result = { component, version, ...status };
  if (!field || !releases) {
    return { ...result, vulnerable: null, upgradeTo: null, missedSecurityReleases: [], cves: [] };
  }
  let latest = null;
  const missed = [];
  for (const release of releases.releases ?? []) {
    const shipped = release?.[field]?.version;
    if (typeof shipped !== "string" || compareVersions(shipped, version) === null) continue;
    if (latest === null || compareVersions(shipped, latest) > 0) latest = shipped;
    if (release.security === true && compareVersions(shipped, version) > 0) missed.push({ release, shipped });
  }
  missed.sort((a, b) => compareVersions(a.shipped, b.shipped));
  const cves = [...new Set(missed.flatMap(({ release }) => (release["cve-list"] ?? []).map((cve) => cve["cve-id"])))]
    .filter(Boolean)
    .sort();
  return {
    ...result,
    vulnerable: missed.length > 0,
    upgradeTo: missed.length ? latest : null,
    missedSecurityReleases: [...new Set(missed.map(({ shipped }) => shipped))],
    cves,
  };
}

// The highest patch of each framework and line is the one apps roll forward to. Older
// side-by-side patches are listed but marked active: false.
export function markActive(runtimes) {
  const best = new Map();
  for (const item of runtimes) {
    const key = `${item.component}|${channelOf(item.version)}`;
    const current = best.get(key);
    if (!current || compareVersions(item.version, current.version) > 0) best.set(key, item);
  }
  return runtimes.map((item) => ({ ...item, active: best.get(`${item.component}|${channelOf(item.version)}`) === item }));
}

export function lowestFix(versions, installed) {
  const later = versions.filter((version) => {
    const cmp = compareVersions(version, installed);
    return cmp !== null && cmp > 0;
  });
  later.sort((a, b) => compareVersions(a, b) ?? 0);
  return later[0] ?? null;
}

function roundUp(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function cvssV3(vector) {
  if (!vector || !vector.startsWith("CVSS:3")) return null;
  const metrics = Object.fromEntries(
    vector
      .split("/")
      .slice(1)
      .map((part) => part.split(":"))
      .filter((pair) => pair.length === 2 && pair[0] && pair[1]),
  );
  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metrics.AV];
  const ac = { L: 0.77, H: 0.44 }[metrics.AC];
  const pr =
    metrics.S === "C"
      ? { N: 0.85, L: 0.68, H: 0.5 }[metrics.PR]
      : { N: 0.85, L: 0.62, H: 0.27 }[metrics.PR];
  const ui = { N: 0.85, R: 0.62 }[metrics.UI];
  const c = { N: 0, L: 0.22, H: 0.56 }[metrics.C];
  const i = { N: 0, L: 0.22, H: 0.56 }[metrics.I];
  const a = { N: 0, L: 0.22, H: 0.56 }[metrics.A];
  if ([av, ac, pr, ui, c, i, a].some((n) => n === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const exploit = 8.22 * av * ac * pr * ui;
  let impact;
  if (metrics.S === "U") impact = 6.42 * iss;
  else impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  if (impact <= 0) return 0;
  const raw =
    metrics.S === "U" ? Math.min(impact + exploit, 10) : Math.min(1.08 * (impact + exploit), 10);
  return roundUp(raw);
}

function numericScore(rec) {
  const db = rec.database_specific ?? {};
  if (typeof db.cvss?.score === "number") return db.cvss.score;
  if (typeof db.cvss_score === "number") return db.cvss_score;
  const scores = (rec.severity ?? [])
    .map((item) => (typeof item.score === "string" ? cvssV3(item.score) : null))
    .filter((n) => n !== null);
  return scores.length ? Math.max(...scores) : null;
}

function publisherSeverity(rec) {
  const raw = rec.database_specific?.severity;
  if (typeof raw !== "string" || !raw.trim()) return null;
  const label = raw.trim().toUpperCase();
  if (label === "MODERATE") return "MEDIUM";
  if (label === "CRITICAL" || label === "HIGH" || label === "MEDIUM" || label === "LOW") return label;
  return null;
}

function labelFromScore(score) {
  if (score === null) return "UNKNOWN";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "UNKNOWN";
}

function fixedVersions(rec, name) {
  const fixed = new Set();
  for (const affected of rec.affected ?? []) {
    const pkg = affected.package;
    if (!pkg || pkg.ecosystem !== ECOSYSTEM || pkg.name?.toLowerCase() !== name.toLowerCase()) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixed.add(event.fixed);
      }
    }
  }
  return [...fixed];
}

class UnionFind {
  constructor() {
    this.parent = new Map();
  }
  find(value) {
    if (!this.parent.has(value)) this.parent.set(value, value);
    const parent = this.parent.get(value);
    if (parent !== value) {
      const root = this.find(parent);
      this.parent.set(value, root);
      return root;
    }
    return value;
  }
  union(a, b) {
    const pa = this.find(a);
    const pb = this.find(b);
    if (pa !== pb) this.parent.set(pa, pb);
  }
}

export function groupRecords(records) {
  const groups = new UnionFind();
  for (const rec of records) {
    for (const alias of rec.aliases ?? []) groups.union(rec.id, alias);
  }
  const buckets = new Map();
  for (const rec of records) {
    if (rec.withdrawn) continue;
    const rootId = groups.find(rec.id);
    if (!buckets.has(rootId)) buckets.set(rootId, []);
    buckets.get(rootId).push(rec);
  }
  return [...buckets.values()];
}

export function summarizeGroup(group, packageName, installed) {
  const published = group.map((rec) => publisherSeverity(rec)).filter((label) => label);
  const pool = published.length ? published : group.map((rec) => labelFromScore(numericScore(rec)));
  pool.sort((a, b) => (RANK[b] ?? 0) - (RANK[a] ?? 0));
  const scores = group.map((rec) => numericScore(rec)).filter((score) => score !== null);
  const primary =
    group.find((rec) => rec.id.startsWith("GHSA-") && rec.summary) ??
    group.find((rec) => rec.id.startsWith("GHSA-")) ??
    group.find((rec) => rec.summary) ??
    group[0];
  const aliases = [...new Set(group.flatMap((rec) => [rec.id, ...(rec.aliases ?? [])]))]
    .filter((id) => id !== primary.id)
    .sort();
  const fixes = [...new Set(group.flatMap((rec) => fixedVersions(rec, packageName)))];
  return {
    id: primary.id,
    aliases,
    summary: primary.summary ?? "",
    severity: pool[0] ?? "UNKNOWN",
    score: scores.length ? Math.max(...scores) : null,
    fixed: lowestFix(fixes, installed),
    url: `https://osv.dev/vulnerability/${primary.id}`,
  };
}

export function upgradeTo(advisories) {
  if (!advisories.every((item) => item.fixed)) return null;
  return advisories.map((item) => item.fixed).sort((a, b) => compareVersions(a, b) ?? 0).at(-1);
}

async function requestJson(url, options) {
  let lastErr;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      const response = await fetch(url, { ...options, signal: AbortSignal.timeout(30000) });
      if (response.status === 429 || response.status >= 500) {
        lastErr = new Error(`${response.status} ${url}`);
        await new Promise((resolve) => setTimeout(resolve, 400 * attempt));
        continue;
      }
      if (!response.ok) {
        const text = await response.text();
        const error = new Error(`${response.status} ${url}: ${text.slice(0, 300)}`);
        error.permanent = true;
        throw error;
      }
      return await response.json();
    } catch (err) {
      if (err.permanent) throw err;
      lastErr = err;
      if (attempt === 4) break;
      await new Promise((resolve) => setTimeout(resolve, 400 * attempt));
    }
  }
  throw lastErr;
}

export function parseArgs(argv) {
  const args = { root: null, dotnetVersion: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--dotnet-version") args.dotnetVersion = argv[++i] ?? "";
    else if (arg.startsWith("--dotnet-version=")) args.dotnetVersion = arg.slice(17);
    else if (args.root === null) args.root = arg;
  }
  return args;
}

async function scanRuntime(dotnetVersion, targets) {
  const source = dotnetVersion === null ? "process" : "flag";
  const runtime = { name: "dotnet", source };
  let runtimes;
  if (source === "flag") {
    if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(dotnetVersion)) {
      return { runtime: { ...runtime, error: "not an exact x.y.z version" }, warnings: [] };
    }
    runtimes = [{ component: "Microsoft.NETCore.App", version: dotnetVersion }];
  } else {
    runtimes = installedRuntimes();
    if (runtimes === null) {
      runtime.note = "dotnet was not found on PATH, so no installed runtime was checked";
      runtimes = [];
    }
  }
  console.error(`dotnet runtimes: ${runtimes.length} (${source}), target frameworks: ${targets.length}`);
  try {
    const index = await requestJson(DOTNET_INDEX);
    const channels = new Set([
      ...runtimes.map((item) => channelOf(item.version)),
      ...targets.map((item) => item.channel),
    ].filter(Boolean));
    const releases = new Map();
    for (const channel of channels) {
      const entry = index["releases-index"]?.find((item) => item["channel-version"] === channel);
      if (entry?.["releases.json"]) releases.set(channel, await requestJson(entry["releases.json"]));
    }
    const installed = markActive(runtimes).map((item) => ({
      ...checkDotnetRuntime(item.component, item.version, index, releases.get(channelOf(item.version))),
      active: item.active,
    }));
    const checkedTargets = targets.map((item) =>
      item.channel ? { ...item, ...channelStatus(item.channel, index) } : item,
    );
    const active = installed.filter((item) => item.active);
    return {
      runtime: {
        ...runtime,
        latestLts: latestLts(index),
        vulnerable: active.length ? active.some((item) => item.vulnerable) : null,
        installed,
        targets: checkedTargets,
      },
      warnings: [],
    };
  } catch (err) {
    const error = `dotnet runtime not checked: ${err.message || err}`;
    return { runtime: { ...runtime, error }, warnings: [error] };
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = path.resolve(args.root || process.cwd());
  const scanned = scanTree(root);
  if (scanned.error) fail(scanned.error);

  const packages = scanned.packages;
  console.error(`manifests: ${scanned.lockfiles.length}`);
  console.error(`package versions: ${packages.length}`);

  const queries = packages.map((pkg) => ({
    version: pkg.version,
    package: { name: pkg.name, ecosystem: ECOSYSTEM },
  }));
  const results = [];
  for (let i = 0; i < queries.length; i += BATCH) {
    const chunk = queries.slice(i, i + BATCH);
    console.error(`querybatch ${i + 1}-${i + chunk.length} of ${queries.length}`);
    const data = await requestJson(`${API}/querybatch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: chunk }),
    });
    if (!Array.isArray(data.results) || data.results.length !== chunk.length) {
      fail(`OSV querybatch returned ${data.results?.length ?? 0} results for ${chunk.length} queries`);
    }
    results.push(...data.results);
  }

  for (let i = 0; i < packages.length; i += 1) {
    let token = results[i]?.next_page_token;
    const vulns = [...(results[i]?.vulns ?? [])];
    while (token) {
      const page = await requestJson(`${API}/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          version: packages[i].version,
          package: { name: packages[i].name, ecosystem: ECOSYSTEM },
          page_token: token,
        }),
      });
      vulns.push(...(page.vulns ?? []));
      token = page.next_page_token;
    }
    packages[i].vulnIds = [...new Set(vulns.map((vuln) => vuln.id))];
  }

  const hits = packages.filter((pkg) => pkg.vulnIds.length);
  const ids = [...new Set(hits.flatMap((pkg) => pkg.vulnIds))];
  console.error(`advisory ids: ${ids.length}`);

  const records = new Map();
  let cursor = 0;
  async function worker() {
    while (cursor < ids.length) {
      const id = ids[cursor];
      cursor += 1;
      records.set(id, await requestJson(`${API}/vulns/${encodeURIComponent(id)}`));
    }
  }
  await Promise.all(Array.from({ length: 12 }, () => worker()));

  const findings = [];
  for (const hit of hits) {
    const present = hit.vulnIds.map((id) => records.get(id)).filter(Boolean);
    const advisories = groupRecords(present)
      .map((group) => summarizeGroup(group, hit.name, hit.version))
      .sort((a, b) => {
        const bySeverity = (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0);
        if (bySeverity !== 0) return bySeverity;
        return (b.score ?? -1) - (a.score ?? -1) || a.id.localeCompare(b.id);
      });
    if (!advisories.length) continue;
    findings.push({
      name: hit.name,
      version: hit.version,
      severity: advisories[0].severity,
      upgradeTo: upgradeTo(advisories),
      locations: hit.locations,
      advisories,
    });
  }

  findings.sort((a, b) => {
    const aProd = a.locations.some((loc) => loc.production) ? 0 : 1;
    const bProd = b.locations.some((loc) => loc.production) ? 0 : 1;
    if (aProd !== bProd) return aProd - bProd;
    const bySev = (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0);
    if (bySev !== 0) return bySev;
    return (
      a.name.localeCompare(b.name) ||
      (compareVersions(a.version, b.version) ?? a.version.localeCompare(b.version))
    );
  });

  console.error(`vulnerable versions: ${findings.length}`);
  const runtime = await scanRuntime(args.dotnetVersion, scanned.targets);
  scanned.warnings.push(...runtime.warnings);
  const report = {
    ecosystem: ECOSYSTEM,
    scannedAt: new Date().toISOString(),
    root: scanned.root,
    lockfiles: scanned.lockfiles,
    packageVersions: packages.length,
    vulnerablePackageVersions: findings.length,
    findings,
    runtime: runtime.runtime,
  };
  if (scanned.warnings.length) report.warnings = scanned.warnings;
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
}

const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (invokedDirectly) {
  main().catch((err) => fail(err.message || String(err)));
}
