// The ERC-8004 link as the registry stores it and a passport carries it: the names and shapes only, so that the
// registry, and a door that reads a passport, need nothing that reads a chain.
import { z } from "zod";

export const ERC8004_REGISTRATION_TYPE = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1";
/** `eip155:<chainId>:<Identity Registry address>`, as ERC-8004 names a registry */
export const ERC8004_REGISTRY = /^eip155:([1-9][0-9]{0,11}):(0x[0-9a-fA-F]{40})$/;

export const Erc8004LinkSchema = z.object({
  agentRegistry: z.string().regex(ERC8004_REGISTRY, { message: "agentRegistry is eip155:<chain id>:<registry address>" }).transform((r) => r.toLowerCase()),
  /** the token id, in decimal: a uint256 does not fit in a JSON number */
  agentId: z.string().regex(/^(0|[1-9][0-9]{0,77})$/, { message: "agentId is the token id in decimal" }).refine((v) => !/^[0-9]+$/.test(v) || BigInt(v) < 2n ** 256n, { message: "agentId is not a uint256" }),
});
export type Erc8004Link = z.infer<typeof Erc8004LinkSchema>;

/** A link as the registry checked it: the token's owner and the block it read, and when. */
export interface Erc8004Checked extends Erc8004Link {
  owner: string;
  block: number;
  /** sha256 of the registration file's bytes */
  fileDigest: string;
  checkedAt: string;
}

export type Erc8004Check = { ok: true; link: Erc8004Checked } | { ok: false; error: string };
