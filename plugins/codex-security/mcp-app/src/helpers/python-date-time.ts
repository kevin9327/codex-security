import { pythonRepr } from "./python-json";

export interface PythonDateTime {
  microseconds: bigint;
  aware: boolean;
}

const dayMicroseconds = 86_400_000_000n;
const failure = (message: string): never => {
  throw Object.assign(new RangeError(message), { name: "ValueError" });
};
const leap = (year: number) =>
  year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
function midnight(year: number, month: number, day: number): Date {
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  return date;
}
function weekOne(year: number): number {
  const fourth = midnight(year, 1, 4);
  return fourth.getTime() - ((fourth.getUTCDay() + 6) % 7) * 86_400_000;
}

function dateSeparator(value: string[]): number {
  if (value.length === 7) return 7;
  if (value[4] === "-") {
    if (value[5] !== "W") return 10;
    if (value[8] !== "-") return 8;
    return /[0-9]/u.test(value[10] ?? "") ? 8 : 10;
  }
  if (value[4] !== "W") return 8;
  let index = 7;
  while (/[0-9]/u.test(value[index] ?? "")) index++;
  return index < 9 ? index : index % 2 === 0 ? 7 : 8;
}

function clock(value: string): number[] | undefined {
  if (value.endsWith("\0") && !/[.,]/u.test(value)) value = value.slice(0, -1);
  const match =
    /^([0-9]{2})(?:(:?)([0-9]{2})(?:\2([0-9]{2}))?)?(?:[.,]([0-9]+))?$(?![\s\S])/u.exec(
      value,
    );
  return match
    ? [
        Number(match[1]),
        Number(match[3] ?? 0),
        Number(match[4] ?? 0),
        Number((match[5] ?? "").slice(0, 6).padEnd(6, "0")),
      ]
    : undefined;
}
function clockMicroseconds(parts: number[]): bigint {
  return (
    BigInt(parts[0]! * 3600 + parts[1]! * 60 + parts[2]!) * 1_000_000n +
    BigInt(parts[3]!)
  );
}
function timedeltaRepr(value: bigint): string {
  const rest = ((value % dayMicroseconds) + dayMicroseconds) % dayMicroseconds;
  const fields: string[] = [];
  const days = (value - rest) / dayMicroseconds;
  if (days) fields.push(`days=${days}`);
  if (rest / 1_000_000n) fields.push(`seconds=${rest / 1_000_000n}`);
  if (rest % 1_000_000n) fields.push(`microseconds=${rest % 1_000_000n}`);
  return `datetime.timedelta(${fields.join(", ") || "0"})`;
}

// datetime.fromisoformat accepts basic dates, ISO weeks and microsecond offsets too.
export function parsePythonDateTime(value: string): PythonDateTime {
  if (typeof value !== "string")
    throw new TypeError("fromisoformat: argument must be str");
  const invalid = () =>
    failure(`Invalid isoformat string: ${pythonRepr(value)}`);
  const characters = Array.from(value);
  if (characters.length < 7) return invalid();
  const separator = dateSeparator(characters);
  const dateText = characters.slice(0, separator).join("");
  const calendar = /^([0-9]{4})(-?)([0-9]{2})\2([0-9]{2})$/u.exec(dateText);
  const week = /^([0-9]{4})(-?)W([0-9]{2})(?:\2([0-9]))?$/u.exec(dateText);
  let year: number, month: number, day: number;
  if (calendar) {
    year = Number(calendar[1]);
    month = Number(calendar[3]);
    day = Number(calendar[4]);
  } else if (week) {
    const weekYear = Number(week[1]),
      number = Number(week[3]),
      weekday = Number(week[4] ?? 1);
    if (
      weekYear < 1 ||
      number < 1 ||
      number > (weekOne(weekYear + 1) - weekOne(weekYear)) / 604_800_000 ||
      weekday < 1 ||
      weekday > 7
    )
      return invalid();
    const date = new Date(
      weekOne(weekYear) + ((number - 1) * 7 + weekday - 1) * 86_400_000,
    );
    year = date.getUTCFullYear();
    month = date.getUTCMonth() + 1;
    day = date.getUTCDate();
  } else return invalid();

  let time = [0, 0, 0, 0],
    offset = 0n,
    aware = false;
  if (characters.length > separator) {
    const text = characters.slice(separator + 1).join("");
    const zone = text.search(/[+\-Z]/u);
    const parsed = clock(zone < 0 ? text : text.slice(0, zone));
    if (parsed === undefined) return invalid();
    time = parsed;
    if (zone >= 0) {
      aware = true;
      if (text[zone] === "Z") {
        if (zone !== text.length - 1 && text[zone + 1] !== "\0")
          return invalid();
      } else {
        const parsedOffset = clock(text.slice(zone + 1));
        if (parsedOffset === undefined) return invalid();
        // CPython treats an offset with zero whole seconds as UTC.
        if (parsedOffset.slice(0, 3).some(Boolean))
          offset =
            clockMicroseconds(parsedOffset) * (text[zone] === "-" ? -1n : 1n);
        if (offset <= -dayMicroseconds || offset >= dayMicroseconds)
          failure(
            "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24), not " +
              timedeltaRepr(offset) +
              ".",
          );
      }
    }
  }
  if (year < 1 || year > 9999) failure(`year ${year} is out of range`);
  if (month < 1 || month > 12) failure("month must be in 1..12");
  const days = [
    31,
    leap(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  if (day < 1 || day > days[month - 1]!)
    failure("day is out of range for month");
  if (time[0]! > 23) failure("hour must be in 0..23");
  if (time[1]! > 59) failure("minute must be in 0..59");
  if (time[2]! > 59) failure("second must be in 0..59");
  return {
    microseconds:
      BigInt(midnight(year, month, day).getTime()) * 1000n +
      clockMicroseconds(time) -
      offset,
    aware,
  };
}
