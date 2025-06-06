/* tslint:disable */
/* eslint-disable */
/**
 * Performs the length extension attack.
 */
export function length_extension_attack(original_message: Uint8Array, original_mac: Uint8Array, data_to_append: Uint8Array, guessed_secret_len: number): ForgedResult;
export class ForgedResult {
  free(): void;
  constructor(message: Uint8Array, digest: Uint8Array);
  readonly message: Uint8Array;
  readonly digest: Uint8Array;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_forgedresult_free: (a: number, b: number) => void;
  readonly forgedresult_new: (a: number, b: number, c: number, d: number) => number;
  readonly forgedresult_message: (a: number) => [number, number];
  readonly forgedresult_digest: (a: number) => [number, number];
  readonly length_extension_attack: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
  readonly __wbindgen_export_0: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
