// CLI entry point: node scripts/generate-vectors.ts [outDir]
import { DEFAULT_VECTOR_DIR, writeSuites } from "../src/index.ts";

const dir = process.argv[2] ?? DEFAULT_VECTOR_DIR;
const paths = await writeSuites(dir);
console.log(`wrote ${paths.length} suites to ${dir}`);
