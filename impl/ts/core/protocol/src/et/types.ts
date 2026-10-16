// Spec §11.2: ET types, labels, methods and limits.
import { Bytes } from "@wake-protocol/bytes";
import { LABELS } from "../spec/labels.ts";

export const ET_REQ_LABEL = LABELS.etReq;
export const ET_RES_LABEL = LABELS.etRes;
export const ET_METHOD_MAX = 32;
export const ET_URL_MAX = 6144;
export const ET_HEADERS_MAX = 8192;
// Covers the longest fixed ET error body produced by the server.
export const ET_BODY_MIN = 1024;
export const ET_BODY_MAX = 1024 * 1024;

const LP_PREFIX_LEN = 4;
// A header pair needs at least one name byte; empty values permit ET_HEADERS_MAX pairs.
const ET_HEADERS_MAX_ENCODED = ET_HEADERS_MAX + 2 * LP_PREFIX_LEN * ET_HEADERS_MAX;

/** §11.2: five outer LP prefixes, label, longest method, longest URL, nested headers and default body. */
export const ET_REQUEST_MAX_ENCODED = 5 * LP_PREFIX_LEN + ET_REQ_LABEL.length + ET_METHOD_MAX
  + ET_URL_MAX + ET_HEADERS_MAX_ENCODED + ET_BODY_MAX;

/** §11.2: four outer LP prefixes, label, u16 status, nested headers and default body. */
export const ET_RESPONSE_MAX_ENCODED = 4 * LP_PREFIX_LEN + ET_RES_LABEL.length + 2
  + ET_HEADERS_MAX_ENCODED + ET_BODY_MAX;

/** A header as a [field name, field value] pair, in received order. */
export type EtHeader = readonly [name: string, value: string];

/** Optional per-deployment settings. */
export interface EtOptions {
  bodyLimit?: number;
}

export interface EtRequest {
  method: string;
  /** Raw URI-reference, not normalized. Must pass checkUrl. */
  url: string;
  headers: readonly EtHeader[];
  body: Bytes;
}

export interface EtResponse {
  status: number;
  headers: readonly EtHeader[];
  body: Bytes;
}
