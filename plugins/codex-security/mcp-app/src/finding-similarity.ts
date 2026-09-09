// Norm and summation adapted from CPython 3.12 mathmodule.c and bltinmodule.c.
// Copyright (c) 2001-2023 Python Software Foundation. PSF License Version 2;
// see the bundled FRONTEND_NOTICES.txt. This TypeScript adaptation replaces
// fused multiplication with exact binary residuals and accepts parsed JSON numbers.
import { JsonFloat, object, objectEntries } from "./helpers/python-json";

const bits = new DataView(new ArrayBuffer(8));
function parts(value: number): [bigint, number] {
  bits.setFloat64(0, value);
  const raw = bits.getBigUint64(0);
  const exponent = Number((raw >> 52n) & 2047n);
  let coefficient = raw & ((1n << 52n) - 1n);
  if (exponent) coefficient |= 1n << 52n;
  if (raw >> 63n) coefficient = -coefficient;
  return [coefficient, exponent === 0 ? -1074 : exponent - 1075];
}

// Round an exact binary product residual once, including subnormal results.
function rounded(coefficient: bigint, exponent: number): number {
  const sign = coefficient < 0n ? -1 : 1;
  if (coefficient < 0n) coefficient = -coefficient;
  const length = coefficient.toString(2).length;
  const shift = Math.max(length - 53, -1074 - exponent);
  if (shift > 0) {
    const divisor = 1n << BigInt(shift);
    const remainder = coefficient % divisor;
    coefficient /= divisor;
    if (
      remainder * 2n > divisor ||
      (remainder * 2n === divisor && coefficient % 2n)
    )
      coefficient++;
    exponent += shift;
  }
  return sign * Number(coefficient) * 2 ** exponent;
}

function product(left: number, right: number): [number, number] {
  const high = left * right;
  // Dekker splitting is exact here: every partial product stays normal, and
  // the split factors and their products cannot overflow.
  if (
    Math.abs(left) >= 2 ** -450 &&
    Math.abs(left) <= 2 ** 450 &&
    Math.abs(right) >= 2 ** -450 &&
    Math.abs(right) <= 2 ** 450
  ) {
    const a = left * 134217729,
      aHigh = a - (a - left),
      aLow = left - aHigh,
      b = right * 134217729,
      bHigh = b - (b - right),
      bLow = right - bHigh;
    const low =
      aLow * bLow - (high - aHigh * bHigh - aLow * bHigh - aHigh * bLow);
    return [high, low];
  }

  const [a, ae] = parts(left),
    [b, be] = parts(right),
    [p, pe] = parts(high);
  const exponent = Math.min(ae + be, pe);
  const residual =
    ((a * b) << BigInt(ae + be - exponent)) - (p << BigInt(pe - exponent));
  return [high, rounded(residual, exponent)];
}

/** Scaled, compensated and corrected norm used by Python 3.12 math.hypot. */
export function vectorNorm(vector: readonly number[]): number {
  let maximum = 0,
    nan = false;
  for (const value of vector) {
    const absolute = Math.abs(value);
    nan ||= Number.isNaN(absolute);
    if (absolute > maximum) maximum = absolute;
  }
  if (maximum === Infinity) return Infinity;
  if (nan) return NaN;
  if (maximum === 0 || vector.length <= 1) return maximum;
  const [coefficient, power] = parts(maximum);
  const exponent = power + coefficient.toString(2).length;
  if (exponent < -1023)
    return vectorNorm(vector.map((value) => value / 2 ** -1022)) * 2 ** -1022;
  const scale = 2 ** -exponent;
  let sum = 1,
    productErrors = 0,
    additionErrors = 0;
  for (const value of vector) {
    const scaled = value * scale;
    const [high, low] = product(scaled, scaled);
    const next = sum + high;
    productErrors += low;
    additionErrors += sum - next + high;
    sum = next;
  }
  let norm = Math.sqrt(sum - 1 + (productErrors + additionErrors));
  const [high, low] = product(-norm, norm);
  const next = sum + high;
  productErrors += low;
  additionErrors += sum - next + high;
  const correction = next - 1 + (productErrors + additionErrors);
  norm += correction / (2 * norm);
  return norm / scale;
}

export class InvalidEmbeddingError extends Error {}

export function normalizedVector(vector: unknown): number[] {
  const elements = Array.isArray(vector)
    ? vector
    : typeof vector === "string"
      ? Array.from(vector)
      : object(vector)
        ? objectEntries(vector).map(([key]) => key)
        : undefined;
  if (elements === undefined)
    throw new TypeError("Stored vector is not iterable");
  const values = elements.map((value: unknown) => {
    if (value instanceof JsonFloat) return Number(value.source);
    if (typeof value === "bigint") {
      const number = Number(value);
      if (!Number.isFinite(number))
        throw new RangeError("int too large to convert to float");
      return number;
    }
    if (typeof value === "boolean") return Number(value);
    if (typeof value !== "number") throw new TypeError("must be real number");
    return value;
  });
  const norm = vectorNorm(values);
  if (norm === 0 || !Number.isFinite(norm))
    throw new InvalidEmbeddingError("A stored embedding cannot be compared.");
  return values.map((value) => value / norm);
}

/** Python 3.12 sum over rounded products, retaining cancellation corrections. */
export function similarity(
  left: readonly number[],
  right: readonly number[],
): number {
  let sum = 0,
    correction = 0;
  for (let index = 0; index < left.length; index++) {
    const value = left[index]! * right[index]!;
    const next = sum + value;
    correction +=
      Math.abs(sum) >= Math.abs(value)
        ? sum - next + value
        : value - next + sum;
    sum = next;
  }
  if (correction && Number.isFinite(correction)) sum += correction;
  return sum;
}
