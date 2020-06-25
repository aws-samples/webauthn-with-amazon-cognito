declare type NativeCrypto = Crypto;
declare type NativeSubtleCrypto = SubtleCrypto;
declare type NativeCryptoKey = CryptoKey;
declare type NativeCryptoKeyPair = CryptoKeyPair;

declare namespace WebcryptoCore {

    const AlgorithmNames: {
        RsaSSA: string;
        RsaPSS: string;
        RsaOAEP: string;
        AesECB: string;
        AesCTR: string;
        AesCMAC: string;
        AesGCM: string;
        AesCBC: string;
        AesKW: string;
        Sha1: string;
        Sha256: string;
        Sha384: string;
        Sha512: string;
        ChaCha20: string;
        EcDSA: string;
        EdDSA: string;
        EcDH: string;
        Hmac: string;
        Poly1305: string;
        Pbkdf2: string;
        X25519: string;
        DesCBC: string;
        DesEdeCBC: string;
    };

    function PrepareAlgorithm(alg: AlgorithmIdentifier | string): Algorithm;
    function PrepareData(data: BufferSource, paramName: string): Uint8Array;

    class BaseCrypto {
        public static checkAlgorithm(alg: Algorithm): void;
        public static checkAlgorithmParams(alg: Algorithm): void;
        public static checkKey(key: CryptoKey, alg?: string, type?: string | null, usage?: string | null): void;
        public static checkWrappedKey(key: CryptoKey): void;
        public static checkKeyUsages(keyUsages: string[]): void;
        public static checkFormat(format: string, type?: string): void;
        public static generateKey(algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair>;
        public static digest(algorithm: Algorithm, data: Uint8Array): PromiseLike<ArrayBuffer>;
        public static sign(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer>;
        public static verify(algorithm: Algorithm, key: CryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean>;
        public static encrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer>;
        public static decrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer>;
        public static deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
        public static deriveKey(algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
        public static importKey(format: string, keyData: JsonWebKey | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public static wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm): PromiseLike<ArrayBuffer>;
        public static unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    }

    class Base64Url {
        public static encode(value: Uint8Array): string;
        public static decode(base64url: string): Uint8Array;
        protected static buffer2string(buffer: Uint8Array): string;
        protected static string2buffer(binaryString: string): Uint8Array;
    }

    class WebCryptoError extends Error {
        public static NOT_SUPPORTED: string;
        public code: number;
        public stack: string;
        constructor(template: string, ...args: any[]);
    }

    class AlgorithmError extends WebCryptoError {
        public static PARAM_REQUIRED: string;
        public static PARAM_WRONG_TYPE: string;
        public static PARAM_WRONG_VALUE: string;
        public static WRONG_ALG_NAME: string;
        public static UNSUPPORTED_ALGORITHM: string;
        public code: number;
    }

    class CryptoKeyError extends WebCryptoError {
        public static EMPTY_KEY: string;
        public static WRONG_KEY_ALG: string;
        public static WRONG_KEY_TYPE: string;
        public static WRONG_KEY_USAGE: string;
        public static NOT_EXTRACTABLE: string;
        public static WRONG_FORMAT: string;
        public static UNKNOWN_FORMAT: string;
        public static ALLOWED_FORMAT: string;
        public code: number;
    }

    class SubtleCrypto implements NativeSubtleCrypto {
        public generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey>;
        public generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;
        public generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public digest(algorithm: AlgorithmIdentifier, data: BufferSource): PromiseLike<ArrayBuffer>;
        public sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer>;
        public verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: BufferSource, data: BufferSource): PromiseLike<boolean>;
        public encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer>;
        public decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer>;
        public deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
        public deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | AesDerivedKeyParams | HmacImportParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
        public exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
        public exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
        public importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public importKey(format: "raw" | "pkcs8" | "spki", keyData: BufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer>;
        public unwrapKey(format: string, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    }

    export class Aes extends BaseCrypto {
        public static checkKeyUsages(keyUsages: string[]): void;
        public static checkAlgorithm(alg: Algorithm): void;
        public static checkKeyGenParams(alg: AesKeyGenParams): void;
        public static checkKeyGenUsages(keyUsages: string[]): void;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }
    export class AesAlgorithmError extends AlgorithmError {
        public code: number;
    }
    export class AesWrapKey extends Aes {
    }
    export class AesEncrypt extends AesWrapKey {
        protected static KEY_USAGES: string[];
    }
    export class AesCBC extends AesEncrypt {
        public static checkAlgorithmParams(alg: AesCbcParams): void;
        protected static ALG_NAME: string;
    }
    export class AesCTR extends AesEncrypt {
        public static checkAlgorithmParams(alg: AesCtrParams): void;
        protected static ALG_NAME: string;
    }
    export class AesGCM extends AesEncrypt {
        public static checkAlgorithmParams(alg: AesGcmParams): void;
        protected static ALG_NAME: string;
    }
    export class AesKW extends AesWrapKey {
        public static checkAlgorithmParams(alg: AesGcmParams): void;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    class EcKeyGenParamsError extends AlgorithmError {
        public code: number;
    }

    class ChaCha20 extends BaseCrypto {
        public static encrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer>;
        public static decrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer>;
        public static ALG_NAME: string;
        public static KEY_USAGES: string[];
    }

    class Ec extends BaseCrypto {
        public static checkAlgorithm(alg: Algorithm): void;
        public static checkKeyGenParams(alg: EcKeyGenParams): void;
        public static checkKeyGenUsages(keyUsages: string[]): void;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    class EcAlgorithmError extends AlgorithmError {
        public code: number;
    }

    class EdDSA extends Ec {
        public static checkAlgorithmParams(alg: EcdsaParams): void;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    class EcDSA extends Ec {
        public static checkAlgorithmParams(alg: EcdsaParams): void;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    class EcDH extends Ec {
        public static checkDeriveParams(algorithm: EcdhKeyDeriveParams): void;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    class RsaKeyGenParamsError extends AlgorithmError {
        public code: number;
    }

    class RsaHashedImportParamsError extends AlgorithmError {
        public code: number;
    }

    class Rsa extends BaseCrypto {
        public static checkAlgorithm(alg: Algorithm): void;
        public static checkImportAlgorithm(alg: RsaHashedImportParams): void;
        public static checkKeyGenParams(alg: RsaHashedKeyGenParams): void;
        public static checkKeyGenUsages(keyUsages: string[]): void;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    class RsaSSA extends Rsa {
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    class RsaPSSParamsError extends AlgorithmError {
        public code: number;
    }

    class RsaPSS extends RsaSSA {
        public static checkRsaPssParams(alg: RsaPssParams): RsaPSSParamsError | undefined;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    class RsaOAEPParamsError extends AlgorithmError {
        public code: number;
    }

    class RsaOAEP extends Rsa {
        public static checkAlgorithmParams(alg: RsaOaepParams): RsaOAEPParamsError | undefined;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    const ShaAlgorithms: string;
    class Sha extends BaseCrypto {
        public static checkAlgorithm(alg: Algorithm): void;
    }

    export class Hmac extends BaseCrypto {
        public static checkAlgorithm(alg: Algorithm): void;
        public static checkKeyGenParams(alg: AesKeyGenParams): void;
        public static checkKeyGenUsages(keyUsages: string[]): void;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    export class Pbkdf2 extends BaseCrypto {
        public static checkAlgorithm(alg: Algorithm): void;
        public static checkDeriveParams(alg: Pbkdf2Params): void;
        protected static ALG_NAME: string;
        protected static KEY_USAGES: string[];
    }

    interface Poly1305KeyGenParams extends Algorithm {
        hash: string | Algorithm;
        length?: number;
    }

    export class Poly1305 extends BaseCrypto {
        public static checkAlgorithm(alg: Algorithm): void;
        public static checkKeyGenParams(alg: Poly1305KeyGenParams): void;
        public static checkKeyGenUsages(keyUsages: string[]): void;
        public static generateKey(algorithm: Poly1305KeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair>;
        public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
        public static importKey(format: string, keyData: JsonWebKey | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public static sign(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer>;
        public static verify(algorithm: Algorithm, key: CryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean>;
        public static ALG_NAME: string;
        public static KEY_USAGES: string[];
    }

    // DES

    interface DesKeyGenParams extends Algorithm {
        length: number;
    }

    interface DesCbcParams extends Algorithm {
        iv: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer;
    }

    interface DesEdeCbcParams extends Algorithm {
        iv: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer;
    }

    interface DesKeyDeriveParams extends Algorithm {
        length: number;
    }

    class Des extends BaseCrypto {
        public static ALG_NAME: string;
        public static KEY_LENGTH: number;
        public static KEY_USAGES: string[];
        public static checkKeyUsages(keyUsages: string[]): void;
        public static checkAlgorithm(alg: Algorithm): void;
        public static checkKeyGenParams(alg: DesKeyGenParams): void;
        public static generateKey(algorithm: DesKeyGenParams, extractable: boolean, keyUsages: string[]): Promise<CryptoKey | CryptoKeyPair>;
        public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
        public static importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public static wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm): PromiseLike<ArrayBuffer>;
        public static unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        public static encrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer>;
        public static decrypt(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer>;
    }

    class DesCBC extends Des {
        public static ALG_NAME: string;
        public static checkAlgorithmParams(alg: DesCbcParams): void;
    }

    class DesEdeCBC extends DesCBC {
        public static ALG_NAME: string;
        public static KEY_LENGTH: number;
    }

}

declare module "webcrypto-core" {
    export = WebcryptoCore;
}
