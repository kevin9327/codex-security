export interface RegexBinding {
  /** Execute trusted SRE bytecode against lossless UTF-16 string units. */
  regexFullMatch(instructions: Uint32Array, units: Uint16Array): boolean;
}
