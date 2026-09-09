import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  checkPythonFreeSource,
  pythonSourceErrors,
} from "../scripts/check-python-free.mjs";

const inspect = (path: string, text: string) =>
  pythonSourceErrors(path, Buffer.from(text));

describe("Python-free source check", () => {
  test("checks the tracked repository inventory without executing scanner input", () => {
    const root = mkdtempSync(join(tmpdir(), "python-source-check-"));
    try {
      execFileSync("git", ["init", "--quiet", root]);
      writeFileSync(
        join(root, "driver.ts"),
        'spawnSync("python3", ["payload.data"]);',
      );
      writeFileSync(
        join(root, "payload.data"),
        'raise RuntimeError("must not execute")',
      );
      writeFileSync(
        join(root, "scanner-input.py"),
        'raise RuntimeError("must not execute")',
      );
      execFileSync("git", ["-C", root, "add", "driver.ts", "payload.data"]);
      expect(checkPythonFreeSource(root)).toEqual({
        files: 2,
        errors: ["driver.ts:1: Python process launch"],
      });
      execFileSync("git", ["-C", root, "add", "scanner-input.py"]);
      expect(checkPythonFreeSource(root).errors).toContain(
        "scanner-input.py: Python source or bytecode",
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects Python source, archives, bytecode and project configuration", () => {
    for (const path of [
      "tool.py",
      "module.pyi",
      "tool.pyw",
      "cache.pyc",
      "cache.pyo",
      "app.pyz",
      "app.pyzw",
      "module.pyd",
      "pyproject.toml",
    ])
      expect(inspect(path, "")).toHaveLength(1);
  });

  test("rejects renamed entrypoints, including a BOM and long shebang", () => {
    expect(
      inspect("tool", "#!/usr/bin/env python3\nprint('example')"),
    ).toHaveLength(1);
    expect(
      inspect("tool.txt", "\uFEFF#!/" + "long/".repeat(80) + "python3.12\n"),
    ).toHaveLength(1);
    expect(inspect("tool", "#!/usr/bin/env node\n")).toEqual([]);
  });

  test("recognizes Python notebook metadata while retaining other languages", () => {
    expect(
      inspect(
        "example.ipynb",
        JSON.stringify({ metadata: { kernelspec: { name: "python3" } } }),
      ),
    ).toHaveLength(1);
    expect(
      inspect(
        "example.ipynb",
        JSON.stringify({ metadata: { language_info: { name: "Python" } } }),
      ),
    ).toHaveLength(1);
    expect(
      inspect(
        "example.ipynb",
        JSON.stringify({ metadata: { language_info: { name: "julia" } } }),
      ),
    ).toEqual([]);
  });

  test("rejects interpreter launches regardless of how their payload is stored", () => {
    for (const source of [
      'execFileSync("python", ["-c", Buffer.from(payload, "base64").toString()]);',
      'spawnSync("/usr/bin/python3.12", ["renamed.data"]);',
      'Bun.spawn(["python3", "-c", payload]);',
      'Bun.spawn({cmd: ["pypy3", "-c", payload]});',
      'native.rawProcess({program: widePath("C:\\\\Python\\\\python.exe"), args: []});',
      'execSync("python3 -c \\"print(1)\\"");',
    ])
      expect(inspect("driver.ts", source)).toHaveLength(1);
  });

  test("retains Python scanner input and names without executing them", () => {
    expect(
      inspect(
        "fixture.ts",
        [
          'const language = "python";',
          'const target = "#!/usr/bin/env python3\\nprint(1)";',
          'writeFileSync("target.py", target);',
          'spawnSync(process.execPath, [helper, "--target", "target.py"]);',
          'const example = `execFileSync("python", ["-c", payload]);`;',
        ].join("\n"),
      ),
    ).toEqual([]);
  });

  test("rejects Python workflow setup and shell commands while retaining absence checks", () => {
    expect(
      inspect("ci.yml", "- uses: actions/setup-python@example"),
    ).toHaveLength(1);
    expect(inspect("ci.yml", "- run: python3 -m pytest")).toHaveLength(1);
    expect(inspect("Dockerfile", "RUN python3 setup.py")).toHaveLength(1);
    expect(
      inspect("check.sh", 'test -z "$(command -v python || true)"'),
    ).toEqual([]);
  });
});
