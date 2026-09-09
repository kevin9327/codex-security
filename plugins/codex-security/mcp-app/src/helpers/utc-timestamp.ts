export function timestamp(microseconds: bigint): string {
  const fraction = ((microseconds % 1_000_000n) + 1_000_000n) % 1_000_000n;
  const seconds = new Date(Number((microseconds - fraction) / 1000n))
    .toISOString()
    .slice(0, -5);
  return `${seconds}${fraction === 0n ? "" : `.${fraction.toString().padStart(6, "0")}`}+00:00`;
}
