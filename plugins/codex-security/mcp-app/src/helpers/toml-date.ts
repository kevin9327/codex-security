// TOML dates retain Python's scalar, comparison, and diagnostic behavior.
export class TomlDate {
  constructor(
    readonly kind: "date" | "datetime" | "time",
    readonly iso: string,
  ) {}

  equals(other: TomlDate): boolean {
    if (this.kind !== other.kind) return false;
    if (this.kind !== "datetime") return this.iso === other.iso;
    const aware = (value: string) => /[+-]\d\d:\d\d$/u.test(value);
    if (aware(this.iso) !== aware(other.iso)) return false;
    if (!aware(this.iso)) return this.iso === other.iso;
    const instant = (value: string) =>
      BigInt(Date.parse(value)) * 1000n +
      BigInt(value.match(/\.\d{3}(\d{3})/u)?.[1] ?? "0");
    return instant(this.iso) === instant(other.iso);
  }

  repr(): string {
    const fields = this.iso.split(/[-T:.+]/u).map(Number);
    if (this.kind === "date") return `datetime.date(${fields.join(", ")})`;
    const clockStart = this.kind === "datetime" ? 3 : 0;
    const count = clockStart + 3;
    const args = fields.slice(0, count);
    const micros = Number(this.iso.match(/\.(\d{6})/u)?.[1] ?? "0");
    if (micros) args.push(micros);
    else if (args.at(-1) === 0) args.pop();
    const offset = this.iso.match(/([+-])(\d\d):(\d\d)$/u);
    let zone = "";
    if (offset && this.kind === "datetime") {
      const seconds = (Number(offset[2]) * 60 + Number(offset[3])) * 60;
      const delta =
        offset[1] === "-"
          ? `days=-1, seconds=${86400 - seconds}`
          : `seconds=${seconds}`;
      zone = seconds
        ? `, tzinfo=datetime.timezone(datetime.timedelta(${delta}))`
        : ", tzinfo=datetime.timezone.utc";
    }
    return `datetime.${this.kind}(${args.join(", ")}${zone})`;
  }
}
