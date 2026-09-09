import { ContractError } from "./scan-contract-errors";

export function validateDateTime(value: string, context: string): void {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.[0-9]+)?(?:[Zz]|[+-](\d{2}):(\d{2}))$(?![\s\S])/u.exec(
      value,
    );
  if (match) {
    const year = Number(match[1]),
      month = Number(match[2]),
      day = Number(match[3]);
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    // fromisoformat normalizes offset minutes before checking the 24-hour bound.
    const offset = Number(match[7] ?? 0) * 60 + Number(match[8] ?? 0);
    if (
      year >= 1 &&
      month >= 1 &&
      month <= 12 &&
      day >= 1 &&
      day <= days[month - 1]! &&
      Number(match[4]) < 24 &&
      Number(match[5]) < 60 &&
      Number(match[6]) < 60 &&
      offset < 1440
    )
      return;
  }
  throw new ContractError(`${context}: expected an RFC 3339 timestamp`);
}
