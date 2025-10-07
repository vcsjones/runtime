// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

import CryptoKit
import Foundation

final class HashBox {
    var value: any HashFunction
    var algorithm : PAL_HashAlgorithm
    init(_ value: any HashFunction, algorithm: PAL_HashAlgorithm) {
        self.value = value
        self.algorithm = algorithm
    }
}

protocol NonceProtocol {
    init<D>(data: D) throws where D : DataProtocol
}

protocol SealedBoxProtocol {
    associatedtype Nonce : NonceProtocol

    var ciphertext: Data { get }
    var tag: Data { get }

    init<C, T>(
        nonce: Nonce,
        ciphertext: C,
        tag: T
    ) throws where C : DataProtocol, T : DataProtocol
}

@available(iOS 13, tvOS 13, *)
protocol AEADSymmetricAlgorithm {
    associatedtype SealedBox : SealedBoxProtocol

    static func seal<Plaintext>(_ plaintext: Plaintext, using key: SymmetricKey, nonce: SealedBox.Nonce?) throws -> SealedBox where Plaintext: DataProtocol
    static func seal<Plaintext, AuthenticatedData>(_ plaintext: Plaintext, using key: SymmetricKey, nonce: SealedBox.Nonce?, authenticating additionalData: AuthenticatedData) throws -> SealedBox where Plaintext: DataProtocol, AuthenticatedData: DataProtocol
    static func open<AuthenticatedData>(_ sealedBox: SealedBox, using key: SymmetricKey, authenticating additionalData: AuthenticatedData) throws -> Data where AuthenticatedData: DataProtocol
    static func open(_ sealedBox: SealedBox, using key: SymmetricKey) throws -> Data
}

@available(iOS 13, tvOS 13, *)
extension AES.GCM.Nonce: NonceProtocol {}

@available(iOS 13, tvOS 13, *)
extension AES.GCM.SealedBox: SealedBoxProtocol {
    typealias Nonce = AES.GCM.Nonce
}

@available(iOS 13, tvOS 13, *)
extension AES.GCM: AEADSymmetricAlgorithm {}

@available(iOS 13, tvOS 13, *)
extension ChaChaPoly.Nonce: NonceProtocol {}

@available(iOS 13, tvOS 13, *)
extension ChaChaPoly.SealedBox: SealedBoxProtocol {
    typealias Nonce = ChaChaPoly.Nonce
}

@available(iOS 13, tvOS 13, *)
extension ChaChaPoly: AEADSymmetricAlgorithm {}

@available(iOS 13, tvOS 13, *)
func encrypt<Algorithm>(
    _ algorithm: Algorithm.Type,
    key: UnsafeBufferPointer<UInt8>,
    nonceData: UnsafeBufferPointer<UInt8>,
    plaintext: UnsafeBufferPointer<UInt8>,
    cipherText: UnsafeMutableBufferPointer<UInt8>,
    tag: UnsafeMutableBufferPointer<UInt8>,
    aad: UnsafeBufferPointer<UInt8>) throws where Algorithm: AEADSymmetricAlgorithm {

    let symmetricKey = SymmetricKey(data: key)

    let nonce = try Algorithm.SealedBox.Nonce(data: nonceData)

    let result = try Algorithm.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: aad)

    // Copy results out of the SealedBox as the Data objects returned here are sometimes slices,
    // which don't have a correct implementation of copyBytes.
    // See https://github.com/apple/swift-foundation/issues/638 for more information.
    let resultCiphertext = Data(result.ciphertext)
    let resultTag = Data(result.tag)

    _ = resultCiphertext.copyBytes(to: cipherText)
    _ = resultTag.copyBytes(to: tag)
}

@available(iOS 13, tvOS 13, *)
func decrypt<Algorithm>(
    _ algorithm: Algorithm.Type,
    key: UnsafeBufferPointer<UInt8>,
    nonceData: UnsafeBufferPointer<UInt8>,
    cipherText: UnsafeBufferPointer<UInt8>,
    tag: UnsafeBufferPointer<UInt8>,
    plaintext: UnsafeMutableBufferPointer<UInt8>,
    aad: UnsafeBufferPointer<UInt8>) throws where Algorithm: AEADSymmetricAlgorithm {

    let symmetricKey = SymmetricKey(data: key)

    let nonce = try Algorithm.SealedBox.Nonce(data: nonceData)

    let sealedBox = try Algorithm.SealedBox(nonce: nonce, ciphertext: cipherText, tag: tag)

    let result = try Algorithm.open(sealedBox, using: symmetricKey, authenticating: aad)

    _ = result.copyBytes(to: plaintext)
}

@_silgen_name("AppleCryptoNative_ChaCha20Poly1305Encrypt")
@available(iOS 13, tvOS 13, *)
public func AppleCryptoNative_ChaCha20Poly1305Encrypt(
    key: UnsafeBufferPointer<UInt8>,
    nonceData: UnsafeBufferPointer<UInt8>,
    plaintext: UnsafeBufferPointer<UInt8>,
    cipherText: UnsafeMutableBufferPointer<UInt8>,
    tag: UnsafeMutableBufferPointer<UInt8>,
    aad: UnsafeBufferPointer<UInt8>
) throws {
    return try encrypt(
        ChaChaPoly.self,
        key: key,
        nonceData: nonceData,
        plaintext: plaintext,
        cipherText: cipherText,
        tag: tag,
        aad: aad)
}

@_silgen_name("AppleCryptoNative_ChaCha20Poly1305Decrypt")
@available(iOS 13, tvOS 13, *)
public func AppleCryptoNative_ChaCha20Poly1305Decrypt(
    key: UnsafeBufferPointer<UInt8>,
    nonceData: UnsafeBufferPointer<UInt8>,
    cipherText: UnsafeBufferPointer<UInt8>,
    tag: UnsafeBufferPointer<UInt8>,
    plaintext: UnsafeMutableBufferPointer<UInt8>,
    aad: UnsafeBufferPointer<UInt8>
) throws {
    return try decrypt(
        ChaChaPoly.self,
        key: key,
        nonceData: nonceData,
        cipherText: cipherText,
        tag: tag,
        plaintext: plaintext,
        aad: aad);
}

@_silgen_name("AppleCryptoNative_AesGcmEncrypt")
@available(iOS 13, tvOS 13, *)
public func AppleCryptoNative_AesGcmEncrypt(
    key: UnsafeBufferPointer<UInt8>,
    nonceData: UnsafeBufferPointer<UInt8>,
    plaintext: UnsafeBufferPointer<UInt8>,
    cipherText: UnsafeMutableBufferPointer<UInt8>,
    tag: UnsafeMutableBufferPointer<UInt8>,
    aad: UnsafeBufferPointer<UInt8>
) throws {
    return try encrypt(
        AES.GCM.self,
        key: key,
        nonceData: nonceData,
        plaintext: plaintext,
        cipherText: cipherText,
        tag: tag,
        aad: aad)
}

@_silgen_name("AppleCryptoNative_AesGcmDecrypt")
@available(iOS 13, tvOS 13, *)
public func AppleCryptoNative_AesGcmDecrypt(
    key: UnsafeBufferPointer<UInt8>,
    nonceData: UnsafeBufferPointer<UInt8>,
    cipherText: UnsafeBufferPointer<UInt8>,
    tag: UnsafeBufferPointer<UInt8>,
    plaintext: UnsafeMutableBufferPointer<UInt8>,
    aad: UnsafeBufferPointer<UInt8>
) throws {
    return try decrypt(
        AES.GCM.self,
        key: key,
        nonceData: nonceData,
        cipherText: cipherText,
        tag: tag,
        plaintext: plaintext,
        aad: aad);
}

@_silgen_name("AppleCryptoNative_IsAuthenticationFailure")
@available(iOS 13, tvOS 13, *)
public func AppleCryptoNative_IsAuthenticationFailure(error: Error) -> Bool {
    if let error = error as? CryptoKitError {
        switch error {
        case .authenticationFailure:
            return true
        default:
            return false
        }
    }
    return false
}

// Must remain in sync with PAL_HashAlgorithm from managed side.
enum PAL_HashAlgorithm: Int32 {
    case unknown = 0
    case md5 = 1
    case sha1 = 2
    case sha256 = 3
    case sha384 = 4
    case sha512 = 5
    case sha3_256 = 6
    case sha3_384 = 7
    case sha3_512 = 8
}

enum DigestError: Error {
    case unknownHashAlgorithm
    case unsupportedHashAlgorithm
}

@_silgen_name("AppleCryptoNative_HKDFExpand")
@available(iOS 14, tvOS 14, *)
public func AppleCryptoNative_HKDFExpand(
    hashAlgorithm: Int32,
    prkPtr: UnsafeMutableRawPointer,
    prkLength: Int32,
    infoPtr: UnsafeMutableRawPointer,
    infoLength: Int32,
    destinationPtr: UnsafeMutablePointer<UInt8>,
    destinationLength: Int32) -> Int32 {

    let prk = Data(bytesNoCopy: prkPtr, count: Int(prkLength), deallocator: Data.Deallocator.none)
    let info = Data(bytesNoCopy: infoPtr, count: Int(infoLength), deallocator: Data.Deallocator.none)
    let destinationLengthInt = Int(destinationLength)

    guard let algorithm = PAL_HashAlgorithm(rawValue: hashAlgorithm) else {
        return -2
    }

    let keyFactory : () throws -> ContiguousBytes = {
        switch algorithm {
            case .unknown:
                throw DigestError.unknownHashAlgorithm
            case .md5:
                return HKDF<Insecure.MD5>.expand(pseudoRandomKey: prk, info: info, outputByteCount: destinationLengthInt)
            case .sha1:
                return HKDF<Insecure.SHA1>.expand(pseudoRandomKey: prk, info: info, outputByteCount: destinationLengthInt)
            case .sha256:
                return HKDF<SHA256>.expand(pseudoRandomKey: prk, info: info, outputByteCount: destinationLengthInt)
            case .sha384:
                return HKDF<SHA384>.expand(pseudoRandomKey: prk, info: info, outputByteCount: destinationLengthInt)
            case .sha512:
                return HKDF<SHA512>.expand(pseudoRandomKey: prk, info: info, outputByteCount: destinationLengthInt)
            case .sha3_256:
                if #available(iOS 26, tvOS 26, macOS 26, *) {
                    return HKDF<SHA3_256>.expand(pseudoRandomKey: prk, info: info, outputByteCount: destinationLengthInt)
                }
                else {
                    throw DigestError.unsupportedHashAlgorithm
                }
            case .sha3_384:
                if #available(iOS 26, tvOS 26, macOS 26, *) {
                    return HKDF<SHA3_384>.expand(pseudoRandomKey: prk, info: info, outputByteCount: destinationLengthInt)
                }
                else {
                    throw DigestError.unsupportedHashAlgorithm
                }
            case .sha3_512:
                if #available(iOS 26, tvOS 26, macOS 26, *) {
                    return HKDF<SHA3_512>.expand(pseudoRandomKey: prk, info: info, outputByteCount: destinationLengthInt)
                }
                else {
                    throw DigestError.unsupportedHashAlgorithm
                }
        }
    }

    guard let key = try? keyFactory() else {
        return -1
    }

    return key.withUnsafeBytes { keyBytes in
        let destination = UnsafeMutableRawBufferPointer(start: destinationPtr, count: destinationLengthInt)
        return Int32(keyBytes.copyBytes(to: destination))
    }
}

@_silgen_name("AppleCryptoNative_HKDFExtract")
@available(iOS 14, tvOS 14, *)
public func AppleCryptoNative_HKDFExtract(
    hashAlgorithm: Int32,
    ikmPtr: UnsafeMutableRawPointer,
    ikmLength: Int32,
    saltPtr: UnsafeMutableRawPointer,
    saltLength: Int32,
    destinationPtr: UnsafeMutablePointer<UInt8>,
    destinationLength: Int32) -> Int32 {

    let ikm = Data(bytesNoCopy: ikmPtr, count: Int(ikmLength), deallocator: Data.Deallocator.none)
    let salt = Data(bytesNoCopy: saltPtr, count: Int(saltLength), deallocator: Data.Deallocator.none)
    let destinationLengthInt = Int(destinationLength)
    let key = SymmetricKey(data: ikm)

    guard let algorithm = PAL_HashAlgorithm(rawValue: hashAlgorithm) else {
        return -2
    }

    let prkFactory : () throws -> ContiguousBytes  = {
        switch algorithm {
            case .unknown:
                throw DigestError.unknownHashAlgorithm
            case .md5:
                return HKDF<Insecure.MD5>.extract(inputKeyMaterial: key, salt: salt)
            case .sha1:
                return HKDF<Insecure.SHA1>.extract(inputKeyMaterial: key, salt: salt)
            case .sha256:
                return HKDF<SHA256>.extract(inputKeyMaterial: key, salt: salt)
            case .sha384:
                return HKDF<SHA384>.extract(inputKeyMaterial: key, salt: salt)
            case .sha512:
                return HKDF<SHA512>.extract(inputKeyMaterial: key, salt: salt)
            case .sha3_256:
                if #available(iOS 26, tvOS 26, macOS 26, *) {
                    return HKDF<SHA3_256>.extract(inputKeyMaterial: key, salt: salt)
                }
                else {
                    throw DigestError.unsupportedHashAlgorithm
                }
            case .sha3_384:
                if #available(iOS 26, tvOS 26, macOS 26, *) {
                    return HKDF<SHA3_384>.extract(inputKeyMaterial: key, salt: salt)
                }
                else {
                    throw DigestError.unsupportedHashAlgorithm
                }
            case .sha3_512:
                if #available(iOS 26, tvOS 26, macOS 26, *) {
                    return HKDF<SHA3_512>.extract(inputKeyMaterial: key, salt: salt)
                }
                else {
                    throw DigestError.unsupportedHashAlgorithm
                }
        }
    }

    guard let prk = try? prkFactory() else {
        return -1
    }

    return prk.withUnsafeBytes { prkBytes in
        let destination = UnsafeMutableRawBufferPointer(start: destinationPtr, count: destinationLengthInt)
        return Int32(prkBytes.copyBytes(to: destination))
    }
}

@_silgen_name("AppleCryptoNative_HKDFDeriveKey")
@available(iOS 14, tvOS 14, *)
public func AppleCryptoNative_HKDFDeriveKey(
    hashAlgorithm: Int32,
    ikmPtr: UnsafeMutableRawPointer,
    ikmLength: Int32,
    saltPtr: UnsafeMutableRawPointer,
    saltLength: Int32,
    infoPtr: UnsafeMutableRawPointer,
    infoLength: Int32,
    destinationPtr: UnsafeMutablePointer<UInt8>,
    destinationLength: Int32) -> Int32 {

    let ikm = Data(bytesNoCopy: ikmPtr, count: Int(ikmLength), deallocator: Data.Deallocator.none)
    let salt = Data(bytesNoCopy: saltPtr, count: Int(saltLength), deallocator: Data.Deallocator.none)
    let info = Data(bytesNoCopy: infoPtr, count: Int(infoLength), deallocator: Data.Deallocator.none)
    let destinationLengthInt = Int(destinationLength)
    let key = SymmetricKey(data: ikm)

    guard let algorithm = PAL_HashAlgorithm(rawValue: hashAlgorithm) else {
        return -2
    }

    let derivedKeyFactory : () throws -> ContiguousBytes = {
        switch algorithm {
            case .unknown:
                throw DigestError.unknownHashAlgorithm
            case .md5:
                return HKDF<Insecure.MD5>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: destinationLengthInt)
            case .sha1:
                return HKDF<Insecure.SHA1>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: destinationLengthInt)
            case .sha256:
                return HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: destinationLengthInt)
            case .sha384:
                return HKDF<SHA384>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: destinationLengthInt)
            case .sha512:
                return HKDF<SHA512>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: destinationLengthInt)
            case .sha3_256:
                if #available(iOS 26, tvOS 26, macOS 26, *) {
                    return HKDF<SHA3_256>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: destinationLengthInt)
                }
                else {
                    throw DigestError.unsupportedHashAlgorithm
                }
            case .sha3_384:
                if #available(iOS 26, tvOS 26, macOS 26, *) {
                    return HKDF<SHA3_384>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: destinationLengthInt)
                }
                else {
                    throw DigestError.unsupportedHashAlgorithm
                }
            case .sha3_512:
                if #available(iOS 26, tvOS 26, macOS 26, *) {
                    return HKDF<SHA3_512>.deriveKey(inputKeyMaterial: key, salt: salt, info: info, outputByteCount: destinationLengthInt)
                }
                else {
                    throw DigestError.unsupportedHashAlgorithm
                }
        }
    }

    guard let derivedKey = try? derivedKeyFactory() else {
        return -1
    }

    return derivedKey.withUnsafeBytes { keyBytes in
        let destination = UnsafeMutableRawBufferPointer(start: destinationPtr, count: destinationLengthInt)
        return Int32(keyBytes.copyBytes(to: destination))
    }
}

@_silgen_name("AppleCryptoNative_Sha3DigestOneShot")
@available(iOS 26, tvOS 26, macOS 26, *)
public func AppleCryptoNative_Sha3DigestOneShot(
    hashAlgorithm: Int32,
    sourcePtr: UnsafeMutableRawPointer,
    sourceLength: Int32,
    destinationPtr: UnsafeMutablePointer<UInt8>,
    destinationLength: Int32,
    digestSizePointer: UnsafeMutablePointer<Int32>?) -> Int32 {

    let source = Data(bytesNoCopy: sourcePtr, count: Int(sourceLength), deallocator: Data.Deallocator.none)
    let destinationLengthInt = Int(destinationLength)

    guard let algorithm = PAL_HashAlgorithm(rawValue: hashAlgorithm) else {
        return -2
    }

    guard let digestSizePointer else {
        return -3
    }

    digestSizePointer.pointee = 0

    let digestFactory : () throws -> (ContiguousBytes, Int) = {
        switch algorithm {
            case .sha3_256:
                return (SHA3_256.hash(data: source), SHA3_256Digest.byteCount)
            case .sha3_384:
                return (SHA3_384.hash(data: source), SHA3_384Digest.byteCount)
            case .sha3_512:
                return (SHA3_512.hash(data: source), SHA3_512Digest.byteCount)
            default:
                throw DigestError.unknownHashAlgorithm
        }
    }

    guard let digest = try? digestFactory() else {
        return -1
    }

    digestSizePointer.pointee = Int32(digest.1)
    _ = digest.0.withUnsafeBytes { digestBytes in
        let destination = UnsafeMutableRawBufferPointer(start: destinationPtr, count: destinationLengthInt)
        digestBytes.copyBytes(to: destination)
    }

    return 1
}

@_silgen_name("AppleCryptoNative_Sha3DigestCreate")
@available(iOS 26, tvOS 26, macOS 26, *)
public func AppleCryptoNative_Sha3DigestCreate(
    hashAlgorithm: Int32,
    digestSizePointer: UnsafeMutablePointer<Int32>?) -> UnsafeMutableRawPointer? {

    guard let digestSizePointer else {
        return nil
    }

    guard let algorithm = PAL_HashAlgorithm(rawValue: hashAlgorithm) else {
        return nil
    }

    switch algorithm {
        case .sha3_256:
            digestSizePointer.pointee = Int32(SHA3_256Digest.byteCount)
            let box = HashBox(SHA3_256(), algorithm: .sha3_256)
            return Unmanaged.passRetained(box).toOpaque()
        case .sha3_384:
            digestSizePointer.pointee = Int32(SHA3_384Digest.byteCount)
            let box = HashBox(SHA3_384(), algorithm: .sha3_384)
            return Unmanaged.passRetained(box).toOpaque()
        case .sha3_512:
            digestSizePointer.pointee = Int32(SHA3_512Digest.byteCount)
            let box = HashBox(SHA3_512(), algorithm: .sha3_512)
            return Unmanaged.passRetained(box).toOpaque()
        default:
            digestSizePointer.pointee = 0
            return nil
    }
}

@_silgen_name("AppleCryptoNative_Sha3DigestUpdate")
@available(iOS 26, tvOS 26, macOS 26, *)
public func AppleCryptoNative_Sha3DigestUpdate(
    hash: UnsafeMutableRawPointer,
    sourcePtr: UnsafeMutableRawPointer,
    sourceLength: Int32) -> Int32 {

    let box = Unmanaged<HashBox>.fromOpaque(hash).takeUnretainedValue()
    let source = Data(bytesNoCopy: sourcePtr, count: Int(sourceLength), deallocator: Data.Deallocator.none)

    switch box.algorithm {
        case .sha3_256:
            var hash = box.value as! SHA3_256
            hash.update(data: source)
            box.value = hash
            return 1
        case .sha3_384:
            var hash = box.value as! SHA3_384
            hash.update(data: source)
            box.value = hash
            return 1
        case .sha3_512:
            var hash = box.value as! SHA3_512
            hash.update(data: source)
            box.value = hash
            return 1
        default:
            return -1
    }
}

@_silgen_name("AppleCryptoNative_Sha3DigestFinal")
@available(iOS 26, tvOS 26, macOS 26, *)
public func AppleCryptoNative_Sha3DigestFinal(
    hash: UnsafeMutableRawPointer,
    destinationPtr: UnsafeMutablePointer<UInt8>,
    destinationLength: Int32) -> Int32 {

    let box = Unmanaged<HashBox>.fromOpaque(hash).takeUnretainedValue()
    let destinationLengthInt = Int(destinationLength)

    let digestFactory : () throws -> ContiguousBytes = {
        switch box.algorithm {
            case .sha3_256:
                return (box.value as! SHA3_256).finalize()
            case .sha3_384:
                return (box.value as! SHA3_384).finalize()
            case .sha3_512:
                return (box.value as! SHA3_512).finalize()
            default:
                throw DigestError.unknownHashAlgorithm
        }
    }

    guard let digest = try? digestFactory() else {
        return -1
    }

    _ = digest.withUnsafeBytes { digestBytes in
        let destination = UnsafeMutableRawBufferPointer(start: destinationPtr, count: destinationLengthInt)
        digestBytes.copyBytes(to: destination)
    }

    return AppleCryptoNative_Sha3DigestReset(hash: hash)
}



@_silgen_name("AppleCryptoNative_Sha3DigestCurrent")
@available(iOS 26, tvOS 26, macOS 26, *)
public func AppleCryptoNative_Sha3DigestCurrent(
    hash: UnsafeMutableRawPointer,
    destinationPtr: UnsafeMutablePointer<UInt8>,
    destinationLength: Int32) -> Int32 {

    let box = Unmanaged<HashBox>.fromOpaque(hash).takeUnretainedValue()
    let destinationLengthInt = Int(destinationLength)

    let digestFactory : () throws -> ContiguousBytes = {
        switch box.algorithm {
            case .sha3_256:
                let hash = box.value as! SHA3_256
                let copy = hash
                return copy.finalize()
            case .sha3_384:
                let hash = box.value as! SHA3_384
                let copy = hash
                return copy.finalize()
            case .sha3_512:
                let hash = box.value as! SHA3_512
                let copy = hash
                return copy.finalize()
            default:
                throw DigestError.unknownHashAlgorithm
        }
    }

    guard let digest = try? digestFactory() else {
        return -1
    }

    _ = digest.withUnsafeBytes { digestBytes in
        let destination = UnsafeMutableRawBufferPointer(start: destinationPtr, count: destinationLengthInt)
        digestBytes.copyBytes(to: destination)
    }

    return 1
}

@_silgen_name("AppleCryptoNative_Sha3DigestFree")
@available(iOS 26, tvOS 26, macOS 26, *)
public func AppleCryptoNative_Sha3DigestFree(ptr: UnsafeMutableRawPointer) {
    Unmanaged<HashBox>.fromOpaque(ptr).release()
}

@_silgen_name("AppleCryptoNative_Sha3DigestReset")
@available(iOS 26, tvOS 26, macOS 26, *)
public func AppleCryptoNative_Sha3DigestReset(hash: UnsafeMutableRawPointer) -> Int32 {
    let box = Unmanaged<HashBox>.fromOpaque(hash).takeUnretainedValue()

    switch box.algorithm {
        case .sha3_256:
            box.value = SHA3_256()
        case .sha3_384:
            box.value = SHA3_384()
        case .sha3_512:
            box.value = SHA3_512()
        default:
            return 0
    }

    return 1
}

@_silgen_name("AppleCryptoNative_Sha3DigestClone")
@available(iOS 26, tvOS 26, macOS 26, *)
public func AppleCryptoNative_Sha3DigestClone(hash: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer? {
    let box = Unmanaged<HashBox>.fromOpaque(hash).takeUnretainedValue()

    switch box.algorithm {
        case .sha3_256:
            let hash = box.value as! SHA3_256
            let copy = hash
            let cloneBox = HashBox(copy, algorithm: .sha3_256)
            return Unmanaged.passRetained(cloneBox).toOpaque()
        case .sha3_384:
            let hash = box.value as! SHA3_384
            let copy = hash
            let cloneBox = HashBox(copy, algorithm: .sha3_384)
            return Unmanaged.passRetained(cloneBox).toOpaque()
        case .sha3_512:
            let hash = box.value as! SHA3_512
            let copy = hash
            let cloneBox = HashBox(copy, algorithm: .sha3_512)
            return Unmanaged.passRetained(cloneBox).toOpaque()
        default:
            return nil
    }
}
