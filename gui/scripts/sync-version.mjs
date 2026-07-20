#!/usr/bin/env node
// Keeps the GUI's version numbers from drifting off the node's. gui/src-tauri is a deliberately
// separate Cargo workspace (see its Cargo.toml comment), so it can't use `version.workspace =
// true` against the root workspace — this is the substitute. Runs as tauri.conf.json's
// beforeBuildCommand/beforeDevCommand, so every `tauri build`/`tauri dev` (local or CI) is
// self-correcting instead of relying on someone remembering to bump three files by hand — which
// is exactly how the GUI ended up shipping "0.7.1" while the workspace had long since moved to
// 0.7.3. tauri.conf.json itself has no hardcoded version — it falls back to src-tauri/Cargo.toml.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const guiDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const rootCargoToml = path.join(guiDir, "..", "Cargo.toml");
const guiCargoToml = path.join(guiDir, "src-tauri", "Cargo.toml");
const guiPackageJson = path.join(guiDir, "package.json");

const rootToml = readFileSync(rootCargoToml, "utf8");
const versionMatches = [...rootToml.matchAll(/^version = "([^"]+)"/gm)];
if (versionMatches.length !== 1) {
  throw new Error(
    `expected exactly one top-level 'version = "..."' line in ${rootCargoToml}, found ${versionMatches.length} — ` +
      "the regex this script relies on may no longer be unambiguous, check Cargo.toml by hand."
  );
}
const version = versionMatches[0][1];

const cargoToml = readFileSync(guiCargoToml, "utf8");
const patched = cargoToml.replace(/^version = "[^"]*"/m, `version = "${version}"`);
if (patched === cargoToml && !cargoToml.includes(`version = "${version}"`)) {
  throw new Error(`could not find a 'version = "..."' line to patch in ${guiCargoToml}`);
}
if (patched !== cargoToml) writeFileSync(guiCargoToml, patched);

const pkg = JSON.parse(readFileSync(guiPackageJson, "utf8"));
if (pkg.version !== version) {
  pkg.version = version;
  writeFileSync(guiPackageJson, JSON.stringify(pkg, null, 2) + "\n");
}

console.log(`gui version synced to ${version} (from ${rootCargoToml})`);
