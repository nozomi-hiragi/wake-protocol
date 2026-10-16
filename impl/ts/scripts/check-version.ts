// Check lockstep release versions and metadata before testing or publishing.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const PUBLISHED = {
  "core/bytes": "@wake-protocol/bytes",
  "core/codec": "@wake-protocol/codec",
  "core/crypto": "@wake-protocol/crypto",
  "core/protocol": "@wake-protocol/core",
  client: "@wake-protocol/client",
  server: "@wake-protocol/server",
};
const DEPENDENCY_SECTIONS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] as const;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

export interface CheckResult {
  errors: string[];
  version: string | null;
}

export function checkVersions(root: string, expectedTag?: string): CheckResult {
  const errors: string[] = [];
  const rootPackage = readJson(join(root, "package.json"));
  const publishedNames = new Set(Object.values(PUBLISHED));
  const versions = new Set<string>();
  for (const [dir, name] of Object.entries(PUBLISHED)) {
    for (const file of ["package.json", "jsr.json"]) {
      const path = join(root, dir, file);
      if (!existsSync(path)) {
        errors.push(`${dir}/${file}: missing`);
        continue;
      }
      const pkg = readJson(path);
      if (pkg.name !== name) errors.push(`${dir}/${file}: expected name ${name}`);
      if (typeof pkg.version !== "string" || !VERSION.test(pkg.version)) {
        errors.push(`${dir}/${file}: expected a plain X.Y.Z version`);
      } else {
        versions.add(pkg.version);
      }
      if (file === "package.json" && pkg.private === true) {
        errors.push(`${dir}/${file}: must not have "private": true`);
      }
    }
  }
  const version = [...versions][0] ?? null;
  if (versions.size !== 1) errors.push(`Version mismatch across packages: ${[...versions].join(", ")}`);
  if (expectedTag !== undefined) {
    const prefix = "impl/ts/v";
    if (!expectedTag.startsWith(prefix) || !VERSION.test(expectedTag.slice(prefix.length))) {
      errors.push(`Tag format unrecognized: ${expectedTag} (expected impl/ts/vX.Y.Z)`);
    } else if (expectedTag.slice(prefix.length) !== version) {
      errors.push(`Tag version ${expectedTag.slice(prefix.length)} does not match package version ${version}`);
    }
  }

  const workspaces = rootPackage.workspaces;
  if (!Array.isArray(workspaces)) throw new Error("Root package workspaces must be an array");
  const dirs = workspaces.flatMap((pattern: string): string[] => {
    if (!pattern.endsWith("/*")) return [pattern];
    const base = pattern.slice(0, -2);
    return readdirSync(join(root, base), { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && existsSync(join(root, base, entry.name, "package.json")))
      .map((entry) => join(base, entry.name));
  });
  for (const dir of [".", ...dirs]) {
    const pkg = readJson(join(root, dir, "package.json"));
    if (!publishedNames.has(String(pkg.name)) && pkg.private !== true) {
      errors.push(`${dir}/package.json: must have "private": true`);
    }
    // Check sections separately: a valid devDependency must not hide a bad runtime dependency.
    for (const section of DEPENDENCY_SECTIONS) {
      const deps = pkg[section] as Record<string, string> | undefined;
      for (const [name, value] of Object.entries(deps ?? {})) {
        if (publishedNames.has(name) && value !== version) {
          errors.push(`${dir}/package.json: ${section} ${name} is ${value}, expected ${version}`);
        }
      }
    }
    for (const file of ["jsr.json", "deno.json"]) {
      if (!existsSync(join(root, dir, file))) continue;
      const config = readJson(join(root, dir, file));
      const imports = config.imports as Record<string, unknown> | undefined;
      for (const [alias, target] of Object.entries(imports ?? {})) {
        const sibling = [...publishedNames].find((name) => alias === name || alias.startsWith(`${name}/`)
          || typeof target === "string" && (target.startsWith(`jsr:${name}@`) || target === `jsr:${name}`));
        if (sibling && (typeof target !== "string"
          || target !== `jsr:${sibling}@${version}` && !target.startsWith(`jsr:${sibling}@${version}/`))) {
          errors.push(`${dir}/${file}: import ${alias} is ${String(target)}, expected jsr:${sibling}@${version}`);
        }
      }
    }
  }

  const rootLicense = readFileSync(join(root, "..", "..", "LICENSE"));
  for (const dir of Object.keys(PUBLISHED)) {
    const path = join(root, dir, "LICENSE");
    if (!existsSync(path)) errors.push(`${dir}/LICENSE: missing`);
    else if (!rootLicense.equals(readFileSync(path))) errors.push(`${dir}/LICENSE: differs from root LICENSE`);
  }
  return { errors, version };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const printVersion = process.argv[2] === "--print-version";
  const { errors, version } = checkVersions(fileURLToPath(new URL("..", import.meta.url)), printVersion ? undefined : process.argv[2]);
  if (errors.length) {
    console.error(errors.join("\n"));
    process.exitCode = 1;
  } else {
    console.log(printVersion ? version : `Version check passed (version: ${version})`);
  }
}
