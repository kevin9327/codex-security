import records from "../../data/workbench-migrations.json";

export type MigrationRecord = readonly [
  version: number,
  name: string,
  sql: string,
];

export const MIGRATIONS: readonly MigrationRecord[] = records.map(
  ({ version, name, sqlLines }) => [version, name, sqlLines.join("\n")],
);
