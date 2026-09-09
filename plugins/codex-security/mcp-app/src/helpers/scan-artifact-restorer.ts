import { readFileSync } from "node:fs";
import { scanRootIdentity, writeScanLocalBytes } from "./scan-local-files";
import { ContractError } from "./scan-contract-errors";

/** Internal SDK transport for the pinned scan root and binary recovery writer. */
export function scanArtifactRestorerCommand(args: string[]): number {
  const [operation, scanDir, relative, dev, ino] = args;
  if (operation === "prepare") {
    const [canonicalPath, identity] = scanRootIdentity(scanDir!);
    console.log(
      JSON.stringify({
        canonicalPath,
        dev: String(identity[0]),
        ino: String(identity[1]),
      }),
    );
    return 0;
  }
  if (operation !== "restore")
    throw new Error("Unknown artifact restoration operation");
  try {
    writeScanLocalBytes(scanDir!, relative!, readFileSync(0), {
      expectedRootIdentity: [BigInt(dev!), BigInt(ino!)],
    });
  } catch (error) {
    if (
      !(error instanceof ContractError) &&
      (error as { errno?: number }).errno === undefined &&
      (error as { winerror?: number }).winerror === undefined
    )
      throw error;
    console.error((error as Error).message);
    return 1;
  }
  return 0;
}
