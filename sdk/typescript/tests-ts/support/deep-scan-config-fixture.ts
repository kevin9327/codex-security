import { readFileSync } from "node:fs";
import {
  DeepScanConfigError,
  deepScanConfigPath,
  resolveDeepScanConfig,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/deep-scan-config";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

const values = parseJson(readFileSync(0, "utf8")) as unknown[];
const results = values.map((value) => {
  try {
    const config = resolveDeepScanConfig(
      (value instanceof JsonFloat ? Number(value.source) : value) as
        | bigint
        | number,
    );
    return {
      config,
      path: deepScanConfigPath(),
      maxTimeType: typeof config.maxTimeHours,
    };
  } catch (error) {
    return {
      error: filesystemErrorMessage(error),
      systemExit: error instanceof DeepScanConfigError,
    };
  }
});
process.stdout.write(stringifyJson(results, { compact: true, sortKeys: true }));
