import assert from "node:assert/strict";
import test from "node:test";
import { releaseNotes } from "./changelog.ts";

test("dated release extracts only the matching section and preserves subheadings", () => {
  const changelog = "# Changelog\n\n## v0.7.0（未リリース）\n\n- Future\n\n## v0.6.0 (2026-10-16)\n\n### Changes\n\n- Released\n\n## v0.5.0 (2026-10-01)\n\n- Earlier\n";
  assert.equal(releaseNotes(changelog, "0.6.0"), "\n### Changes\n\n- Released\n\n");
});

test("unreleased heading is rejected", () => {
  assert.throws(() => releaseNotes("## v0.6.0（未リリース）\n\n- Pending\n", "0.6.0"), /Expected exactly one CHANGELOG heading/);
});

test("missing release is rejected without matching a different version", () => {
  assert.throws(() => releaseNotes("## v0.6.10 (2026-10-16)\n\n- Other\n", "0.6.1"), /Expected exactly one CHANGELOG heading/);
});

for (const date of ["2026-02-29", "2026-02-30", "2026-04-31", "2026-13-01", "2026-00-10", "2026-01-00"]) {
  test(`invalid calendar date ${date} is rejected`, () => {
    assert.throws(() => releaseNotes(`## v0.6.0 (${date})\n`, "0.6.0"), /Invalid CHANGELOG release date/);
  });
}

for (const heading of ["## v0.6.0 (2026-1-01)", "## v0.6.0 (YYYY-MM-DD)", "## v0.6.0 (2026-10-16) extra", "### v0.6.0 (2026-10-16)"]) {
  test(`inexact heading ${JSON.stringify(heading)} is rejected`, () => {
    assert.throws(() => releaseNotes(`${heading}\n`, "0.6.0"), /Expected exactly one CHANGELOG heading/);
  });
}

test("last section extends to EOF, including a missing final newline", () => {
  assert.equal(releaseNotes("# Changelog\n\n## v0.6.0 (2024-02-29)\n\n- Last", "0.6.0"), "\n- Last");
});

test("CRLF headings and section boundaries are supported", () => {
  assert.equal(releaseNotes("## v0.6.0 (2026-10-16)\r\n\r\n- Released\r\n## Older\r\n- Earlier\r\n", "0.6.0"), "\n- Released\n");
});

test("duplicate dated sections are rejected", () => {
  assert.throws(() => releaseNotes("## v0.6.0 (2026-10-16)\n- One\n## v0.6.0 (2026-10-17)\n- Two\n", "0.6.0"), /Expected exactly one CHANGELOG heading/);
});

test("invalid version is rejected", () => {
  assert.throws(() => releaseNotes("## v0.6.0 (2026-10-16)\n", "0.6.0-alpha"), /Invalid release version/);
});
