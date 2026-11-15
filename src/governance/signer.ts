import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  createHash,
  KeyObject,
} from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface Verifier {
  readonly publicKeyHex: string;
  verify(message: string, signatureB64: string): boolean;
}
export interface Signer extends Verifier {
  sign(message: string): string;
}

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex'); // fixed DER prefix of an Ed25519 SPKI key

export function fingerprint(publicKeyHex: string): string {
  return createHash('sha256').update(Buffer.from(publicKeyHex, 'hex')).digest('hex').slice(0, 16);
}

function publicKeyToHex(pub: KeyObject): string {
  const der = pub.export({ type: 'spki', format: 'der' });
  return der.subarray(SPKI_PREFIX.length).toString('hex');
}

function publicKeyFromHex(hex: string): KeyObject {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('Ed25519 public key must be 32 bytes (64 hex chars)');
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(hex, 'hex')]), format: 'der', type: 'spki' });
}

/** Verify-only handle from a hex public key (what `audit verify --pubkey` uses). */
export function verifierFromHex(publicKeyHex: string): Verifier {
  const key = publicKeyFromHex(publicKeyHex);
  return {
    publicKeyHex: publicKeyHex.toLowerCase(),
    verify(message, signatureB64) {
      try {
        return edVerify(null, Buffer.from(message, 'utf8'), key, Buffer.from(signatureB64, 'base64'));
      } catch {
        return false;
      }
    },
  };
}

export class Ed25519Signer implements Signer {
  readonly publicKeyHex: string;
  private readonly verifierImpl: Verifier;
  private constructor(private readonly priv: KeyObject) {
    this.publicKeyHex = publicKeyToHex(createPublicKey(priv));
    this.verifierImpl = verifierFromHex(this.publicKeyHex);
  }

  static generate(): Ed25519Signer {
    const { privateKey } = generateKeyPairSync('ed25519');
    return new Ed25519Signer(privateKey);
  }

  /**
   * Load the key from `<stateDir>/audit.key` or create it (mode 0600 on POSIX).
   * On Windows chmod is largely a no-op: the file inherits the ACL of the state directory.
   */
  static loadOrCreate(stateDir: string): Ed25519Signer {
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    const keyPath = path.join(stateDir, 'audit.key');
    if (fs.existsSync(keyPath)) {
      return new Ed25519Signer(createPrivateKey(fs.readFileSync(keyPath, 'utf8')));
    }
    const s = Ed25519Signer.generate();
    const pem = s.priv.export({ type: 'pkcs8', format: 'pem' }) as string;
    fs.writeFileSync(keyPath, pem, { mode: 0o600, flag: 'wx' });
    fs.writeFileSync(path.join(stateDir, 'audit.pub'), s.publicKeyHex + '\n', { mode: 0o644 });
    return s;
  }

  sign(message: string): string {
    return edSign(null, Buffer.from(message, 'utf8'), this.priv).toString('base64');
  }

  verify(message: string, signatureB64: string): boolean {
    return this.verifierImpl.verify(message, signatureB64);
  }
}
