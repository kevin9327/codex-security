import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

type Table = Record<string, unknown>;
function object(value: unknown): Table {
  expect(value).not.toBeNull();
  expect(typeof value).toBe("object");
  expect(Array.isArray(value)).toBe(false);
  return value as Table;
}
function text(value: unknown): string {
  expect(typeof value).toBe("string");
  expect((value as string).trim()).not.toBe("");
  return value as string;
}
function strings(value: unknown): string[] {
  expect(Array.isArray(value)).toBe(true);
  expect((value as unknown[]).length).toBeGreaterThan(0);
  return (value as unknown[]).map(text);
}
const read = (path: string) => readFileSync(join(PLUGIN_ROOT, path), "utf8");

test("the packaged plugin manifest references its assets and skill directory", () => {
  const manifest = object(JSON.parse(read(".codex-plugin/plugin.json")));
  expect(manifest["name"]).toBe("codex-security");
  expect(text(manifest["version"])).toMatch(/^\d+\.\d+\.\d+(?:-alpha)?$/);
  text(manifest["description"]);
  expect(manifest["author"]).toEqual({ name: "OpenAI" });
  for (const field of ["homepage", "repository"])
    expect(text(manifest[field])).toStartWith("https://");
  text(manifest["license"]);
  strings(manifest["keywords"]);
  expect(manifest["skills"]).toBe("./skills/");
  expect(
    statSync(join(PLUGIN_ROOT, manifest["skills"] as string)).isDirectory(),
  ).toBe(true);
  expect(manifest["mcpServers"]).toBe("./.mcp.json");
  expect(
    statSync(join(PLUGIN_ROOT, manifest["mcpServers"] as string)).isFile(),
  ).toBe(true);
  const ui = object(manifest["interface"]);
  expect(ui["displayName"]).toBe("Codex Security");
  for (const field of [
    "shortDescription",
    "longDescription",
    "developerName",
    "category",
  ])
    text(ui[field]);
  for (const field of ["websiteURL", "privacyPolicyURL", "termsOfServiceURL"])
    expect(text(ui[field])).toStartWith("https://");
  for (const field of ["capabilities", "defaultPrompt"]) strings(ui[field]);
  expect(text(ui["brandColor"])).toMatch(/^#[0-9A-Fa-f]{6}$/);
  expect(Array.isArray(ui["screenshots"])).toBe(true);
  for (const field of ["composerIcon", "logo"]) {
    const path = text(ui[field]);
    expect(path).toStartWith("./");
    expect(statSync(join(PLUGIN_ROOT, path)).isFile()).toBe(true);
  }
});

test("the packaged skills have YAML metadata and usable agent interfaces", () => {
  const directories = readdirSync(join(PLUGIN_ROOT, "skills"), {
    withFileTypes: true,
  })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  expect(directories.length).toBeGreaterThan(0);
  for (const name of directories) {
    const skill = read(`skills/${name}/SKILL.md`);
    const frontmatter = /^---\n([\s\S]*?)\n---\n/.exec(skill);
    expect(frontmatter, name).not.toBeNull();
    const metadata = object(Bun.YAML.parse(frontmatter![1]!));
    expect(Object.keys(metadata).sort()).toEqual(["description", "name"]);
    expect(metadata["name"]).toBe(name);
    text(metadata["description"]);
    const agent = object(
      Bun.YAML.parse(read(`skills/${name}/agents/openai.yaml`)),
    );
    const ui = object(agent["interface"]);
    for (const field of ["display_name", "short_description", "default_prompt"])
      text(ui[field]);
  }
});
