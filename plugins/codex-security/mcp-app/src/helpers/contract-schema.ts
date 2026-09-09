import { validateDateTime } from "./contract-date-time";
import { fullPatternMatch } from "./python-regex";
import { JsonFloat, object, objectEntries, pythonRepr } from "./python-json";
import { ContractError } from "./scan-contract-errors";

type Numeric = number | bigint | JsonFloat;

type SchemaType =
  | "array"
  | "boolean"
  | "integer"
  | "number"
  | "object"
  | "string"
  | "null";
export interface ContractSchema {
  $ref?: string;
  type?: SchemaType | SchemaType[];
  const?: unknown;
  enum?: unknown[];
  minLength?: Numeric;
  pattern?: string;
  format?: string;
  minimum?: Numeric;
  maximum?: Numeric;
  minItems?: Numeric;
  maxItems?: Numeric;
  uniqueItems?: boolean;
  contains?: ContractSchema;
  minContains?: Numeric;
  maxContains?: Numeric;
  items?: ContractSchema;
  allOf?: ContractSchema[];
  if?: ContractSchema;
  then?: ContractSchema;
  required?: string[];
  minProperties?: Numeric;
  properties?: Record<string, ContractSchema>;
  additionalProperties?: boolean | ContractSchema;
  [key: string]: unknown;
}

const numeric = (value: unknown): value is Numeric =>
  typeof value === "number" ||
  typeof value === "bigint" ||
  value instanceof JsonFloat;
const number = (value: Numeric) =>
  value instanceof JsonFloat ? Number(value.source) : value;

function typeName(value: unknown): string {
  if (value === null) return "NoneType";
  if (Array.isArray(value)) return "list";
  if (typeof value === "boolean") return "bool";
  if (typeof value === "string") return "str";
  if (numeric(value))
    return value instanceof JsonFloat ||
      (typeof value === "number" && !Number.isInteger(value))
      ? "float"
      : "int";
  return object(value) ? "dict" : typeof value;
}

function operationError(name: string, message: string): never {
  const error = new Error(message);
  error.name = name;
  throw error;
}

function get(value: unknown, key: string, fallback: unknown = null): unknown {
  if (!object(value))
    operationError(
      "AttributeError",
      `'${typeName(value)}' object has no attribute 'get'`,
    );
  return Object.hasOwn(value, key) ? value[key] : fallback;
}

function hashable(value: unknown): void {
  if (Array.isArray(value) || object(value))
    throw new TypeError(`unhashable type: '${typeName(value)}'`);
}

function* iterate(value: unknown): Generator<unknown> {
  if (Array.isArray(value) || typeof value === "string") yield* value;
  else if (object(value)) for (const [key] of objectEntries(value)) yield key;
  else throw new TypeError(`'${typeName(value)}' object is not iterable`);
}

function truthy(value: unknown): boolean {
  if (numeric(value)) return number(value) !== 0 && number(value) !== 0n;
  if (Array.isArray(value) || typeof value === "string")
    return value.length > 0;
  if (object(value)) return Object.keys(value).length > 0;
  return Boolean(value);
}

function compare(left: Numeric, right: unknown, operator: "<" | ">"): boolean {
  if (!numeric(right) && typeof right !== "boolean")
    throw new TypeError(
      `'${operator}' not supported between instances of '${typeName(left)}' and '${typeName(right)}'`,
    );
  const a = number(left),
    b = typeof right === "boolean" ? Number(right) : number(right);
  return operator === "<" ? a < b : a > b;
}

function equal(left: unknown, right: unknown): boolean {
  if (numeric(left) && numeric(right)) {
    const a = number(left),
      b = number(right);
    if (typeof a === typeof b) return a === b;
    const integer = typeof a === "bigint" ? a : b;
    const floating = typeof a === "number" ? a : (b as number);
    return (
      Number.isFinite(floating) &&
      Number.isInteger(floating) &&
      integer === BigInt(floating)
    );
  }
  if (Array.isArray(left))
    return (
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((value, index) => equal(value, right[index]))
    );
  if (object(left))
    return (
      object(right) &&
      Object.keys(left).length === Object.keys(right).length &&
      objectEntries(left).every(
        ([key, value]) => Object.hasOwn(right, key) && equal(value, right[key]),
      )
    );
  return left === right;
}

function matches(value: unknown, expected: unknown): boolean {
  switch (expected) {
    case "array":
      return Array.isArray(value);
    case "boolean":
      return typeof value === "boolean";
    case "integer":
      return (
        typeof value === "bigint" ||
        (typeof value === "number" && Number.isInteger(value))
      );
    case "number":
      return numeric(value);
    case "object":
      return object(value);
    case "string":
      return typeof value === "string";
    case "null":
      return value === null;
  }
  hashable(expected);
  return operationError("KeyError", pythonRepr(expected));
}

/** Validate the structural rules shared by assessments and scan contracts. */
export function validateAgainstSchema(
  value: unknown,
  schema: ContractSchema,
  context: string,
  root: ContractSchema = schema,
): void {
  const fail: (message: string) => never = (message) => {
    throw new ContractError(`${context}: ${message}`);
  };
  const reference = get(schema, "$ref");
  if (reference !== null) {
    if (typeof reference !== "string")
      fail("schema reference must be a string");
    let target: unknown = root;
    if (reference !== "#") {
      if (!reference.startsWith("#/"))
        fail(`unsupported schema reference ${pythonRepr(reference)}`);
      for (const part of reference.slice(2).split("/")) {
        const key = part.replaceAll("~1", "/").replaceAll("~0", "~");
        if (!object(target) || !Object.hasOwn(target, key))
          fail(`unresolved schema reference ${pythonRepr(reference)}`);
        target = target[key];
      }
    }
    if (!object(target))
      fail(`schema reference ${pythonRepr(reference)} is not an object`);
    validateAgainstSchema(value, target as ContractSchema, context, root);
  }
  const expected = schema.type;
  if (Array.isArray(expected)) {
    if (!expected.some((type) => matches(value, type)))
      fail(`does not match schema type ${pythonRepr(expected)}`);
  } else if (typeof expected === "string" && !matches(value, expected)) {
    fail(`expected schema type ${expected}`);
  }
  if (Object.hasOwn(schema, "const") && !equal(value, schema.const))
    fail(`expected ${pythonRepr(schema.const)}`);
  if (Object.hasOwn(schema, "enum")) {
    let found = false;
    for (const candidate of iterate(schema.enum))
      if (equal(value, candidate)) {
        found = true;
        break;
      }
    if (!found) fail(`unsupported value ${pythonRepr(value)}`);
  }
  if (typeof value === "string") {
    if (
      truthy(schema.minLength) &&
      compare(Array.from(value).length, schema.minLength, "<")
    )
      fail("string is too short");
    if (Object.hasOwn(schema, "pattern")) {
      const pattern = schema.pattern;
      if (typeof pattern !== "string") {
        hashable(pattern);
        throw new TypeError(
          "first argument must be string or compiled pattern",
        );
      }
      if (!fullPatternMatch(pattern, value))
        fail("string does not match schema pattern");
    }
    if (schema.format === "date-time") validateDateTime(value, context);
  }
  if (numeric(value)) {
    if (Object.hasOwn(schema, "minimum") && compare(value, schema.minimum, "<"))
      fail("value is below schema minimum");
    if (Object.hasOwn(schema, "maximum") && compare(value, schema.maximum, ">"))
      fail("value is above schema maximum");
  }
  if (Array.isArray(value)) {
    if (
      Object.hasOwn(schema, "minItems") &&
      compare(value.length, schema.minItems, "<")
    )
      fail("array has too few items");
    if (
      Object.hasOwn(schema, "maxItems") &&
      compare(value.length, schema.maxItems, ">")
    )
      fail("array has too many items");
    if (
      schema.uniqueItems === true &&
      value.some((item, index) =>
        value.slice(0, index).some((other) => equal(item, other)),
      )
    )
      fail("array items must be unique");
    if (object(schema.contains)) {
      let count = 0;
      for (const item of value) {
        try {
          validateAgainstSchema(item, schema.contains, context, root);
          count++;
        } catch (error) {
          if (!(error instanceof ContractError)) throw error;
        }
      }
      if (compare(count, get(schema, "minContains", 1), "<"))
        fail("array contains too few matching items");
      if (
        Object.hasOwn(schema, "maxContains") &&
        compare(count, schema.maxContains, ">")
      )
        fail("array contains too many matching items");
    }
    if (object(schema.items))
      value.forEach((item, index) =>
        validateAgainstSchema(
          item,
          schema.items!,
          `${context}[${index}]`,
          root,
        ),
      );
  }
  if (object(value)) {
    for (const child of iterate(get(schema, "allOf", [])))
      validateAgainstSchema(value, child as ContractSchema, context, root);
    if (object(schema.if)) {
      let matches = true;
      try {
        validateAgainstSchema(value, schema.if, context, root);
      } catch (error) {
        if (!(error instanceof ContractError)) throw error;
        matches = false;
      }
      if (matches && object(schema.then))
        validateAgainstSchema(value, schema.then, context, root);
    }
    for (const key of iterate(get(schema, "required", []))) {
      hashable(key);
      if (typeof key !== "string" || !Object.hasOwn(value, key))
        throw new ContractError(
          `${context}.${typeof key === "string" ? key : pythonRepr(key)}: missing required schema property`,
        );
    }
    if (
      Object.hasOwn(schema, "minProperties") &&
      compare(Object.keys(value).length, schema.minProperties, "<")
    )
      fail("object has too few properties");
    const properties = get(schema, "properties", {});
    for (const [key, item] of objectEntries(value)) {
      const child = get(properties, key);
      if (object(child))
        validateAgainstSchema(item, child, `${context}.${key}`, root);
      else if (schema.additionalProperties === false)
        throw new ContractError(
          `${context}.${key}: unexpected schema property`,
        );
      else if (object(schema.additionalProperties))
        validateAgainstSchema(
          item,
          schema.additionalProperties,
          `${context}.${key}`,
          root,
        );
    }
  }
}
