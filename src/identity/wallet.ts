/**
 * Automaton Wallet Management
 *
 * Creates and manages wallets for the automaton's identity and payments.
 * Supports both EVM (secp256k1/viem) and Solana (Ed25519/tweetnacl) wallets.
 * The private key is the automaton's sovereign identity.
 * Chain type is chosen at genesis and never changes.
 */

import type { PrivateKeyAccount } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import nacl from "tweetnacl";
import bs58 from "bs58";
import fs from "fs";
import path from "path";
import type { WalletData } from "../types.js";
import type { ChainType } from "./chain.js";
import { EvmChainIdentity, SolanaChainIdentity } from "./chain.js";
import type { ChainIdentity } from "./chain.js";
import {
  encryptString,
  decryptString,
  getMasterPassword,
  looksEncrypted,
  KEYSTORE_VERSION,
} from "./keystore.js";

/**
 * Create a stub PrivateKeyAccount for Solana wallets.
 * The stub has the Solana address but throws on any EVM signing attempt,
 * preventing accidental use of a random key.
 */
function createSolanaStubAccount(solanaAddress: string): PrivateKeyAccount {
  const throwSigning = () => {
    throw new Error(
      "Cannot use EVM signing methods on a Solana wallet. Use chainIdentity instead.",
    );
  };
  return {
    address: solanaAddress as any,
    publicKey: "0x" as any,
    source: "custom",
    type: "local",
    signMessage: throwSigning as any,
    signTypedData: throwSigning as any,
    signTransaction: throwSigning as any,
    sign: throwSigning as any,
  } as unknown as PrivateKeyAccount;
}

const AUTOMATON_DIR = path.join(
  process.env.HOME || "/root",
  ".automaton",
);
const WALLET_FILE = path.join(AUTOMATON_DIR, "wallet.json");

export function getAutomatonDir(): string {
  return AUTOMATON_DIR;
}

export function getWalletPath(): string {
  return WALLET_FILE;
}

/**
 * Generate a Solana Ed25519 keypair.
 * Returns the 64-byte secret key (first 32 = private, last 32 = public).
 */
export function generateSolanaKeypair(): { secretKey: Uint8Array; publicKey: Uint8Array; address: string } {
  const keypair = nacl.sign.keyPair();
  return {
    secretKey: keypair.secretKey,
    publicKey: keypair.publicKey,
    address: bs58.encode(keypair.publicKey),
  };
}

/**
 * Get or create the automaton's wallet.
 * The private key IS the automaton's identity -- protect it.
 *
 * @param chainType - If creating a new wallet, which chain to use. Defaults to "evm".
 */
export async function getWallet(chainType?: ChainType): Promise<{
  account: PrivateKeyAccount;
  chainIdentity: ChainIdentity;
  chainType: ChainType;
  isNew: boolean;
}> {
  if (!fs.existsSync(AUTOMATON_DIR)) {
    fs.mkdirSync(AUTOMATON_DIR, { recursive: true, mode: 0o700 });
  }

  if (fs.existsSync(WALLET_FILE)) {
    const walletData: WalletData = JSON.parse(
      fs.readFileSync(WALLET_FILE, "utf-8"),
    );
    const resolvedChainType = walletData.chainType || "evm";

    if (resolvedChainType === "solana" && walletData.secretKey) {
      const secretKeyB58 = walletData.encrypted
        ? decryptString(walletData.secretKey, getMasterPassword())
        : walletData.secretKey;
      const secretKey = bs58.decode(secretKeyB58);
      const solanaIdentity = new SolanaChainIdentity(secretKey);
      const account = createSolanaStubAccount(solanaIdentity.address);
      return { account, chainIdentity: solanaIdentity, chainType: "solana", isNew: false };
    }

    // EVM path (default)
    const privateKey = walletData.encrypted
      ? (decryptString(walletData.privateKey as string, getMasterPassword()) as `0x${string}`)
      : (walletData.privateKey as `0x${string}`);
    const account = privateKeyToAccount(privateKey);
    return { account, chainIdentity: new EvmChainIdentity(account), chainType: "evm", isNew: false };
  }

  // Create new wallet
  const resolvedChain = chainType || "evm";

  if (resolvedChain === "solana") {
    const { secretKey, address } = generateSolanaKeypair();
    const solanaIdentity = new SolanaChainIdentity(secretKey);

    const walletData: WalletData = {
      chainType: "solana",
      secretKey: bs58.encode(secretKey),
      createdAt: new Date().toISOString(),
    };

    fs.writeFileSync(WALLET_FILE, JSON.stringify(walletData, null, 2), {
      mode: 0o600,
    });

    const account = createSolanaStubAccount(address);
    return { account, chainIdentity: solanaIdentity, chainType: "solana", isNew: true };
  }

  // EVM wallet
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);

  const walletData: WalletData = {
    chainType: "evm",
    privateKey,
    createdAt: new Date().toISOString(),
  };

  fs.writeFileSync(WALLET_FILE, JSON.stringify(walletData, null, 2), {
    mode: 0o600,
  });

  return { account, chainIdentity: new EvmChainIdentity(account), chainType: "evm", isNew: true };
}

/**
 * Get the wallet address without loading the full account.
 * For encrypted wallets this still needs the master password — the address
 * is derived from the (encrypted) private key.
 */
export function getWalletAddress(): string | null {
  if (!fs.existsSync(WALLET_FILE)) {
    return null;
  }

  const walletData: WalletData = JSON.parse(
    fs.readFileSync(WALLET_FILE, "utf-8"),
  );

  if (walletData.chainType === "solana" && walletData.secretKey) {
    const secretKeyB58 = walletData.encrypted
      ? decryptString(walletData.secretKey, getMasterPassword())
      : walletData.secretKey;
    const secretKey = bs58.decode(secretKeyB58);
    const keypair = nacl.sign.keyPair.fromSecretKey(secretKey);
    return bs58.encode(keypair.publicKey);
  }

  const privateKey = walletData.encrypted
    ? (decryptString(walletData.privateKey as string, getMasterPassword()) as `0x${string}`)
    : (walletData.privateKey as `0x${string}`);
  const account = privateKeyToAccount(privateKey);
  return account.address;
}

/**
 * Load the full wallet account (needed for signing).
 * For Solana wallets, returns a proxy account.
 * For encrypted wallets this requires AUTOMATON_MASTER_PASSWORD.
 */
export function loadWalletAccount(): PrivateKeyAccount | null {
  if (!fs.existsSync(WALLET_FILE)) {
    return null;
  }

  const walletData: WalletData = JSON.parse(
    fs.readFileSync(WALLET_FILE, "utf-8"),
  );

  if (walletData.chainType === "solana") {
    // Solana wallets don't have a PrivateKeyAccount; callers should use getWallet() instead
    return null;
  }

  const privateKey = walletData.encrypted
    ? (decryptString(walletData.privateKey as string, getMasterPassword()) as `0x${string}`)
    : (walletData.privateKey as `0x${string}`);
  return privateKeyToAccount(privateKey);
}

/**
 * Get the chain type from the wallet file.
 */
export function getWalletChainType(): ChainType {
  if (!fs.existsSync(WALLET_FILE)) {
    return "evm";
  }
  try {
    const walletData: WalletData = JSON.parse(
      fs.readFileSync(WALLET_FILE, "utf-8"),
    );
    return walletData.chainType || "evm";
  } catch {
    return "evm";
  }
}

/**
 * Migrate a plaintext wallet to the AES-256-GCM keystore format.
 *
 * Idempotent: if the wallet is already encrypted, returns { migrated: false }
 * without touching the file. Backs up the prior file to
 * wallet.json.preEncrypt.<unix-ts>.bak before rewriting.
 *
 * The operator must persist AUTOMATON_MASTER_PASSWORD before the next start;
 * if the password is lost the wallet is unrecoverable from the encrypted file
 * alone (the backup retains the plaintext form so recovery is possible from
 * an offsite copy of that backup — handle it like any other secret).
 */
export function migrateWalletToEncrypted(passphrase: string): {
  migrated: boolean;
  walletFile: string;
  backupFile?: string;
} {
  if (!fs.existsSync(WALLET_FILE)) {
    throw new Error(`no wallet to migrate at ${WALLET_FILE}`);
  }
  if (!passphrase || passphrase.length < 8) {
    throw new Error("passphrase must be at least 8 characters");
  }
  const walletData: WalletData = JSON.parse(
    fs.readFileSync(WALLET_FILE, "utf-8"),
  );
  if (walletData.encrypted) {
    return { migrated: false, walletFile: WALLET_FILE };
  }

  const backupFile = `${WALLET_FILE}.preEncrypt.${Math.floor(Date.now() / 1000)}.bak`;
  fs.copyFileSync(WALLET_FILE, backupFile);
  // Defensive: the backup still holds plaintext, so lock it down. The wallet
  // file itself was already mode 0o600; mirror that on the backup.
  fs.chmodSync(backupFile, 0o600);

  const next: WalletData = {
    ...walletData,
    encrypted: true,
    encryptionVersion: KEYSTORE_VERSION,
  };

  if (walletData.chainType === "solana" && walletData.secretKey) {
    next.secretKey = encryptString(walletData.secretKey, passphrase);
  } else if (walletData.privateKey) {
    next.privateKey = encryptString(walletData.privateKey, passphrase);
  } else {
    throw new Error("wallet has neither privateKey nor secretKey to encrypt");
  }

  fs.writeFileSync(WALLET_FILE, JSON.stringify(next, null, 2), { mode: 0o600 });
  return { migrated: true, walletFile: WALLET_FILE, backupFile };
}

/**
 * Reverse migration — only useful as an emergency recovery tool. Will throw
 * if the passphrase is wrong (the GCM auth tag will fail validation).
 */
export function decryptWalletToPlaintext(passphrase: string): {
  decrypted: boolean;
  walletFile: string;
  backupFile?: string;
} {
  if (!fs.existsSync(WALLET_FILE)) {
    throw new Error(`no wallet at ${WALLET_FILE}`);
  }
  const walletData: WalletData = JSON.parse(
    fs.readFileSync(WALLET_FILE, "utf-8"),
  );
  if (!walletData.encrypted) {
    return { decrypted: false, walletFile: WALLET_FILE };
  }
  const backupFile = `${WALLET_FILE}.encrypted.${Math.floor(Date.now() / 1000)}.bak`;
  fs.copyFileSync(WALLET_FILE, backupFile);
  fs.chmodSync(backupFile, 0o600);
  const next: WalletData = { ...walletData };
  delete next.encrypted;
  delete next.encryptionVersion;
  if (walletData.chainType === "solana" && walletData.secretKey) {
    next.secretKey = decryptString(walletData.secretKey, passphrase);
  } else if (walletData.privateKey) {
    next.privateKey = decryptString(walletData.privateKey as string, passphrase) as `0x${string}`;
  }
  fs.writeFileSync(WALLET_FILE, JSON.stringify(next, null, 2), { mode: 0o600 });
  return { decrypted: true, walletFile: WALLET_FILE, backupFile };
}

/** Is the on-disk wallet encrypted? Cheap check that doesn't need the password. */
export function isWalletEncrypted(): boolean {
  if (!fs.existsSync(WALLET_FILE)) return false;
  try {
    const walletData: WalletData = JSON.parse(
      fs.readFileSync(WALLET_FILE, "utf-8"),
    );
    return walletData.encrypted === true;
  } catch {
    return false;
  }
}

export function walletExists(): boolean {
  return fs.existsSync(WALLET_FILE);
}
