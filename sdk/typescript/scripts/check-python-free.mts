// Source inventory complements the build and runtime checks with Python unavailable.
import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync, readlinkSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const pythonFile = /\.(?:py|pyi|pyw|pyc|pyo|pyz|pyzw|pyd)$/iu;
const pythonProgram =
  /(?:^|[\\/])(?:python(?:\d+(?:\.\d+)*)?|pypy\d*)(?:\.exe)?$/iu;
const processCalls =
  /^(?:exec|execSync|execFile|execFileSync|execFileAsync|spawn|spawnSync|rawProcess|bareCommand)$/u;

function literal(node: ts.Node | undefined): string | undefined {
  if (node && ts.isStringLiteralLike(node)) return node.text;
  // These are the ordinary byte/path encoders used by the native process adapter.
  if (node && ts.isCallExpression(node)) {
    const name = node.expression.getText();
    if (["Buffer.from", "widePath", "utf8Bytes"].includes(name))
      return literal(node.arguments[0]);
  }
  return undefined;
}

function program(node: ts.Expression | undefined): string | undefined {
  if (node && ts.isArrayLiteralExpression(node))
    return literal(node.elements[0]);
  if (node && ts.isObjectLiteralExpression(node)) {
    for (const property of node.properties) {
      if (!ts.isPropertyAssignment(property)) continue;
      const key = ts.isIdentifier(property.name)
        ? property.name.text
        : literal(property.name);
      if (key === "cmd" || key === "program")
        return program(property.initializer);
    }
  }
  return literal(node);
}

export function pythonSourceErrors(path: string, bytes: Buffer): string[] {
  if (pythonFile.test(path)) return [`${path}: Python source or bytecode`];
  if (basename(path) === "pyproject.toml")
    return [`${path}: Python project configuration`];
  const content = bytes.toString("utf8");
  const firstLine = content.replace(/^\uFEFF/u, "").split(/[\r\n]/u, 1)[0]!;
  if (/^#![^\r\n]*\b(?:python\d*(?:\.\d+)*|pypy\d*)\b/iu.test(firstLine))
    return [`${path}: Python shebang`];
  if (/\.ipynb$/iu.test(path)) {
    const notebook = JSON.parse(content) as {
      metadata?: { kernelspec?: unknown; language_info?: unknown };
    };
    if (
      /python|pypy/iu.test(
        JSON.stringify([
          notebook.metadata?.kernelspec,
          notebook.metadata?.language_info,
        ]),
      )
    )
      return [`${path}: Python notebook`];
  }
  const errors: string[] = [];
  if (/\.[cm]?[jt]sx?$/iu.test(path)) {
    const source = ts.createSourceFile(
      path,
      content,
      ts.ScriptTarget.Latest,
      true,
    );
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const name = ts.isPropertyAccessExpression(node.expression)
          ? node.expression.name.text
          : ts.isIdentifier(node.expression)
            ? node.expression.text
            : "";
        if (processCalls.test(name)) {
          const command = program(node.arguments[0]);
          // exec uses a shell; other process APIs receive the executable itself.
          const executable =
            name === "exec" || name === "execSync"
              ? command
                  ?.match(/^\s*(?:"([^"]+)"|'([^']+)'|(\S+))/u)
                  ?.slice(1)
                  .find(Boolean)
              : command;
          if (executable && pythonProgram.test(executable)) {
            const line =
              source.getLineAndCharacterOfPosition(node.getStart(source)).line +
              1;
            errors.push(`${path}:${line}: Python process launch`);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  if (/\.(?:sh|ya?ml)$/iu.test(path) || basename(path) === "Dockerfile") {
    content.split(/\r?\n/u).forEach((line, index) => {
      if (
        /^\s*(?:-\s*run:\s*|RUN\s+)?(?:python(?:\d+(?:\.\d+)*)?|pypy\d*)(?:\s|$)/u.test(
          line,
        ) ||
        /^\s*(?:-\s*)?uses:\s*actions\/setup-python@/u.test(line)
      )
        errors.push(`${path}:${index + 1}: Python build or CI command`);
    });
  }
  return errors;
}

export function checkPythonFreeSource(root: string): {
  files: number;
  errors: string[];
} {
  const tracked = spawnSync("git", ["ls-files", "-z"], {
    cwd: root,
    maxBuffer: Infinity,
  });
  if (tracked.error) throw tracked.error;
  if (tracked.status !== 0)
    throw new Error(tracked.stderr.toString() || "git ls-files failed");
  const paths = tracked.stdout.toString().split("\0").filter(Boolean);
  const errors: string[] = [];
  for (const path of paths) {
    const absolute = resolve(root, path);
    if (lstatSync(absolute).isSymbolicLink()) {
      // Inspect the link name/target without following it outside the checkout.
      if (pythonFile.test(path) || pythonFile.test(readlinkSync(absolute)))
        errors.push(`${path}: Python source link`);
      continue;
    }
    errors.push(...pythonSourceErrors(path, readFileSync(absolute)));
  }
  return { files: paths.length, errors };
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  const result = checkPythonFreeSource(root);
  if (result.errors.length) {
    console.error(result.errors.join("\n"));
    process.exitCode = 1;
  } else
    console.log(
      `Python-free source check passed: ${result.files} tracked files.`,
    );
}
