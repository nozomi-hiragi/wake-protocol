// Validate a dated release heading and extract its notes for GitHub Releases.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export function releaseNotes(changelog: string, version: string): string {
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) {
    throw new Error(`Invalid release version: ${version}`);
  }
  const lines = changelog.split(/\r?\n/);
  const heading = new RegExp(`^## v${version.replaceAll(".", "\\.")} \\((\\d{4}-\\d{2}-\\d{2})\\)$`);
  const matches = lines.flatMap((line, index) => {
    const match = heading.exec(line);
    return match ? [{ index, date: match[1]! }] : [];
  });
  if (matches.length !== 1) {
    throw new Error(`Expected exactly one CHANGELOG heading: ## v${version} (YYYY-MM-DD)`);
  }
  const { index, date } = matches[0]!;
  const parsed = new Date(`${date}T00:00:00.000Z`);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== date) {
    throw new Error(`Invalid CHANGELOG release date: ${date}`);
  }
  const next = lines.findIndex((line, i) => i > index && line.startsWith("## "));
  return lines.slice(index + 1, next === -1 ? undefined : next).join("\n") + (next === -1 ? "" : "\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [version, outFile] = process.argv.slice(2);
  if (!version || !outFile || process.argv.length !== 4) {
    console.error("Usage: node scripts/changelog.ts <version> <out-file>");
    process.exitCode = 1;
  } else {
    try {
      const changelog = readFileSync(new URL("../../../CHANGELOG.md", import.meta.url), "utf8");
      writeFileSync(outFile, releaseNotes(changelog, version));
    } catch (error) {
      console.error(error instanceof Error ? error.message : error);
      process.exitCode = 1;
    }
  }
}
