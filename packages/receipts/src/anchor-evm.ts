// The anchor's chain on Ethereum or any other EVM chain: one zero-value transaction from the anchor's address to
// itself, the root in its calldata. Signing needs viem, an optional dependency loaded here only, so the verifier side
// never needs it.
import type { AnchorChain } from "./anchor.ts";

export interface EvmChainOptions {
  /** a JSON-RPC endpoint; read from the environment by the CLI, since a provider's URL often carries its key */
  rpcUrl: string;
  /** the anchor key, 0x-prefixed hex; from the environment, never a flag */
  privateKey: string;
  /** 1, Ethereum mainnet, by default; `resolveAnchorChain` turns a name such as "base" into its id */
  chainId?: number;
  /** a run whose fees would exceed this many gwei per gas is skipped, not sent */
  maxFeeGwei: number;
  /** an EIP-1193 provider in place of `rpcUrl`, for tests */
  provider?: { request(args: { method: string; params?: unknown }): Promise<unknown> };
}

export async function evmChain(o: EvmChainOptions): Promise<AnchorChain> {
  let viem: typeof import("viem");
  let accounts: typeof import("viem/accounts");
  let known: typeof import("viem/chains");
  try {
    viem = await import("viem");
    accounts = await import("viem/accounts");
    known = await import("viem/chains");
  } catch (cause) {
    throw new Error("anchoring needs the optional package viem; install it beside @agent-custody/receipts", { cause });
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(o.privateKey)) throw new Error("the anchor key must be 32 bytes of 0x-prefixed hex");
  if (!(o.maxFeeGwei > 0)) throw new Error("the fee cap must be a positive number of gwei");
  const account = accounts.privateKeyToAccount(o.privateKey as `0x${string}`);
  const chainId = o.chainId ?? 1;
  // viem's own definition where it has one, for a chain's formatters (the OP Stack's, say); a bare one otherwise
  const chain = (Object.values(known) as unknown[]).find((c): c is import("viem").Chain => typeof c === "object" && c !== null && (c as { id?: unknown }).id === chainId) ?? viem.defineChain({ id: chainId, name: `chain ${chainId}`, nativeCurrency: { name: "native", symbol: "NATIVE", decimals: 18 }, rpcUrls: { default: { http: [o.rpcUrl] } } });
  const transport = o.provider ? viem.custom(o.provider) : viem.http(o.rpcUrl, { timeout: 30_000, retryCount: 2 });
  const client = viem.createWalletClient({ account, chain, transport }).extend(viem.publicActions);
  const remote = await client.getChainId();
  if (remote !== chainId) throw new Error(`the endpoint is chain ${remote}, expected ${chainId}`);
  const cap = viem.parseGwei(String(o.maxFeeGwei));
  return {
    chainId,
    address: account.address.toLowerCase(),
    async send(data) {
      const fees = await client.estimateFeesPerGas();
      if (fees.maxFeePerGas > cap) throw new Error(`fees are ${viem.formatGwei(fees.maxFeePerGas)} gwei per gas, above the cap of ${o.maxFeeGwei}`);
      return client.sendTransaction({ to: account.address, value: 0n, data: data as `0x${string}`, maxFeePerGas: fees.maxFeePerGas, maxPriorityFeePerGas: fees.maxPriorityFeePerGas });
    },
    async included(txHash) {
      try {
        const r = await client.getTransactionReceipt({ hash: txHash as `0x${string}` });
        return { blockNumber: Number(r.blockNumber), ok: r.status === "success" };
      } catch (e) {
        if (e instanceof viem.TransactionReceiptNotFoundError) return null;
        throw e;
      }
    },
  };
}
