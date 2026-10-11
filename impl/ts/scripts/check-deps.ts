// Enforce dependency directions, declarations and package-local relative imports.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { isBuiltin } from "node:module";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const allowedEdges: Record<string, readonly string[]> = {
  "@wake-protocol/bytes": [],
  "@wake-protocol/codec": [],
  "@wake-protocol/crypto": ["@scure/base"],
  "@wake-protocol/core": ["@wake-protocol/bytes", "@wake-protocol/codec", "@wake-protocol/crypto", "@scure/base"],
  "@wake-protocol/vectors": ["@wake-protocol/core", "@wake-protocol/bytes", "@wake-protocol/codec", "@scure/base"],
  "@wake-protocol/server": ["@wake-protocol/core", "@wake-protocol/bytes", "@wake-protocol/codec", "@wake-protocol/crypto", "@scure/base"],
  "@wake-protocol/client": ["@wake-protocol/core", "@wake-protocol/bytes", "@wake-protocol/codec", "@wake-protocol/crypto", "@scure/base"],
};

const readPackage = (dir: string) => JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));

function files(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? files(path) : path.endsWith(".ts") ? [path] : [];
  });
}

export function checkDependencies(root: string): { offenders: string[]; count: number } {
  const rootDev = Object.keys(readPackage(root).devDependencies ?? {});
  const offenders: string[] = [];
  let count = 0;
  for (const entry of readdirSync(join(root, "packages"), { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = join(root, "packages", entry.name);
    const pkg = readPackage(dir);
    const allowed = new Set(allowedEdges[pkg.name] ?? []);
    const dependencies = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies, ...pkg.optionalDependencies });
    // src/ must declare its imports as runtime dependencies (not devDependencies).
    const runtime = new Set(Object.keys({ ...pkg.dependencies, ...pkg.peerDependencies, ...pkg.optionalDependencies }));
    // A root dev dependency may be declared only as this package's devDependencies, never as a runtime dependency.
    const ownDev = new Set(Object.keys(pkg.devDependencies ?? {}));
    count++;
    if (!(pkg.name in allowedEdges)) offenders.push(`${relative(root, dir)}: unknown package ${pkg.name}`);
    for (const name of dependencies) {
      const rootDevOk = ownDev.has(name) && !runtime.has(name) && rootDev.includes(name) && !name.startsWith("@wake-protocol/");
      if (!allowed.has(name) && !rootDevOk) {
        offenders.push(`${relative(root, join(dir, "package.json"))}: ${name} (forbidden dependency)`);
      }
    }
    for (const area of ["src", "test", "scripts"]) {
      // Root devDependencies (typescript, @types/node) are allowed only in test and script code.
      const devArea = area !== "src";
      const declared = devArea ? new Set([...rootDev, ...dependencies]) : runtime;
      for (const file of files(join(dir, area))) {
        const imports = ts.preProcessFile(readFileSync(file, "utf8"), true, true).importedFiles;
        for (const { fileName: specifier } of imports) {
          let reason = "";
          if (specifier.startsWith(".")) {
            const target = relative(dir, resolve(dirname(file), specifier));
            if (target === ".." || target.startsWith("../") || isAbsolute(target)) reason = "relative import leaves package";
          } else if (!isBuiltin(specifier)) {
            const name = specifier.startsWith("@") ? specifier.split("/").slice(0, 2).join("/") : specifier.split("/")[0]!;
            const rootDevOk = devArea && rootDev.includes(name) && !name.startsWith("@wake-protocol/");
            if (!allowed.has(name) && !rootDevOk) reason = "forbidden dependency";
            else if (!declared.has(name)) reason = "undeclared dependency";
          }
          if (reason) offenders.push(`${relative(root, file)}: ${specifier} (${reason})`);
        }
      }
    }
  }
  return { offenders, count };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const root = resolve(process.argv[2] ?? fileURLToPath(new URL("..", import.meta.url)));
  const { offenders, count } = checkDependencies(root);
  if (offenders.length) {
    console.error(offenders.join("\n"));
    process.exitCode = 1;
  } else {
    console.log(`Dependency check passed (${count} packages).`);
  }
}
