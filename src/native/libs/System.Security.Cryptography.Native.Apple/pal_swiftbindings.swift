// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

import CryptoKit
import Foundation

@_cdecl("AppleCryptoNative_Ed25519Generate")
public func AppleCryptoNative_Ed25519Generate(
    privateKeyBuffer: UnsafeMutablePointer<UInt8>,
    privateKeyBufferLength: Int32,
    publicKeyBuffer: UnsafeMutablePointer<UInt8>,
    publicKeyBufferLength: Int32,
    privateKeyWritten: UnsafeMutablePointer<Int32>,
    publicKeyWritten: UnsafeMutablePointer<Int32>
) -> Int32 {
    privateKeyWritten.initialize(to: 0)
    publicKeyWritten.initialize(to: 0)
    let privateKey = Curve25519.Signing.PrivateKey.init()
    let privateBytes = privateKey.rawRepresentation
    let publicKey = privateKey.publicKey
    let publicBytes = publicKey.rawRepresentation

    if (privateBytes.count > privateKeyBufferLength) {
        return 0
    }

    if (publicBytes.count > publicKeyBufferLength) {
        return 0
    }

    privateBytes.copyBytes(to: privateKeyBuffer, count: privateBytes.count)
    publicBytes.copyBytes(to: publicKeyBuffer, count: publicBytes.count)
    privateKeyWritten.initialize(to: Int32(privateBytes.count))
    publicKeyWritten.initialize(to: Int32(publicBytes.count))

    return 1
}

@_cdecl("AppleCryptoNative_Ed25519Sign")
public func AppleCryptoNative_Ed25519Sign(
    privateKeyPtr: UnsafeMutableRawPointer,
    privateKeyLength: Int32,
    dataPtr: UnsafeMutableRawPointer,
    dataLength: Int32,
    signatureBuffer: UnsafeMutablePointer<UInt8>,
    signatureBufferLength: Int32,
    signatureWritten: UnsafeMutablePointer<Int32>
) -> Int32 {
    signatureWritten.initialize(to: 0)
    let privateKeyData = Data(bytesNoCopy: privateKeyPtr, count: Int(privateKeyLength), deallocator: Data.Deallocator.none)
    let data = Data(bytesNoCopy: dataPtr, count: Int(dataLength), deallocator: Data.Deallocator.none)

    guard let privateKey = try? Curve25519.Signing.PrivateKey.init(rawRepresentation: privateKeyData) else {
        return 0
    }

    guard let signature = try? privateKey.signature(for: data) else {
        return 0
    }

    if (signature.count < signatureBufferLength) {
        return 0
    }

    signature.copyBytes(to: signatureBuffer, count: signature.count)
    signatureWritten.initialize(to: Int32(signature.count))
    return 1
}

@_cdecl("AppleCryptoNative_Ed25519Verify")
public func AppleCryptoNative_Ed25519Verify(
    publicKeyPtr: UnsafeMutableRawPointer,
    publicKeyLength: Int32,
    dataPtr: UnsafeMutableRawPointer,
    dataLength: Int32,
    signaturePtr: UnsafeMutableRawPointer,
    signatureLength: Int32,
    validSignature: UnsafeMutablePointer<Int32>
) -> Int32 {
    validSignature.initialize(to: 0)
    let publicKeyData = Data(bytesNoCopy: publicKeyPtr, count: Int(publicKeyLength), deallocator: Data.Deallocator.none)
    let data = Data(bytesNoCopy: dataPtr, count: Int(dataLength), deallocator: Data.Deallocator.none)
    let signature = Data(bytesNoCopy: signaturePtr, count: Int(signatureLength), deallocator: Data.Deallocator.none)

    guard let publicKey = try? Curve25519.Signing.PublicKey.init(rawRepresentation: publicKeyData) else {
        return 0
    }

    let valid = publicKey.isValidSignature(signature, for: data)

    if (valid) {
        validSignature.initialize(to: 1)
    }

    return 1
}

@_cdecl("AppleCryptoNative_Ed25519ValidPublicKey")
public func AppleCryptoNative_Ed25519ValidPublicKey(
    publicKeyPtr: UnsafeMutableRawPointer,
    publicKeyLength: Int32
) -> Int32 {
    let publicKeyData = Data(bytesNoCopy: publicKeyPtr, count: Int(publicKeyLength), deallocator: Data.Deallocator.none)

    if let _ = try? Curve25519.Signing.PublicKey.init(rawRepresentation: publicKeyData) {
        return 1
    } else {
        return 0
    }
}

@_cdecl("AppleCryptoNative_Ed25519ValidPrivateKey")
public func AppleCryptoNative_Ed25519ValidPrivateKey(
    privateKeyPtr: UnsafeMutableRawPointer,
    privateKeyLength: Int32,
    publicKeyBuffer: UnsafeMutablePointer<UInt8>,
    publicKeyBufferLength: Int32,
    publicKeyWritten: UnsafeMutablePointer<Int32>,
    validPrivateKey: UnsafeMutablePointer<Int32>
) -> Int32 {
    publicKeyWritten.initialize(to: 0)
    validPrivateKey.initialize(to: 0)
    let privateKeyData = Data(bytesNoCopy: privateKeyPtr, count: Int(privateKeyLength), deallocator: Data.Deallocator.none)

    guard let privateKey = try? Curve25519.Signing.PrivateKey.init(rawRepresentation: privateKeyData) else {
        return 1
    }

    let publicKeyData = privateKey.publicKey.rawRepresentation

    if (publicKeyBufferLength < publicKeyData.count) {
        return 0
    }

    publicKeyData.copyBytes(to: publicKeyBuffer, count: publicKeyData.count)
    publicKeyWritten.initialize(to: Int32(publicKeyData.count))
    validPrivateKey.initialize(to: 1)
    return 1
}

@_cdecl("AppleCryptoNative_ChaCha20Poly1305Encrypt")
public func AppleCryptoNative_ChaCha20Poly1305Encrypt(
    keyPtr: UnsafeMutableRawPointer,
    keyLength: Int32,
    noncePtr: UnsafeMutableRawPointer,
    nonceLength: Int32,
    plaintextPtr: UnsafeMutableRawPointer,
    plaintextLength: Int32,
    ciphertextBuffer: UnsafeMutablePointer<UInt8>,
    ciphertextBufferLength: Int32,
    tagBuffer: UnsafeMutablePointer<UInt8>,
    tagBufferLength: Int32,
    aadPtr: UnsafeMutableRawPointer,
    aadLength: Int32
 ) -> Int32 {
    let nonceData = Data(bytesNoCopy: noncePtr, count: Int(nonceLength), deallocator: Data.Deallocator.none)
    let key = Data(bytesNoCopy: keyPtr, count: Int(keyLength), deallocator: Data.Deallocator.none)
    let plaintext = Data(bytesNoCopy: plaintextPtr, count: Int(plaintextLength), deallocator: Data.Deallocator.none)
    let aad = Data(bytesNoCopy: aadPtr, count: Int(aadLength), deallocator: Data.Deallocator.none)
    let symmetricKey = SymmetricKey(data: key)

    guard let nonce = try? ChaChaPoly.Nonce(data: nonceData) else {
        return 0
    }

    guard let result = try? ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: aad) else {
        return 0
    }

    assert(ciphertextBufferLength >= result.ciphertext.count)
    assert(tagBufferLength >= result.tag.count)

    result.ciphertext.copyBytes(to: ciphertextBuffer, count: result.ciphertext.count)
    result.tag.copyBytes(to: tagBuffer, count: result.tag.count)
    return 1
 }

@_cdecl("AppleCryptoNative_ChaCha20Poly1305Decrypt")
public func AppleCryptoNative_ChaCha20Poly1305Decrypt(
    keyPtr: UnsafeMutableRawPointer,
    keyLength: Int32,
    noncePtr: UnsafeMutableRawPointer,
    nonceLength: Int32,
    ciphertextPtr: UnsafeMutableRawPointer,
    ciphertextLength: Int32,
    tagPtr: UnsafeMutableRawPointer,
    tagLength: Int32,
    plaintextBuffer: UnsafeMutablePointer<UInt8>,
    plaintextBufferLength: Int32,
    aadPtr: UnsafeMutableRawPointer,
    aadLength: Int32
) -> Int32 {
    let nonceData = Data(bytesNoCopy: noncePtr, count: Int(nonceLength), deallocator: Data.Deallocator.none)
    let key = Data(bytesNoCopy: keyPtr, count: Int(keyLength), deallocator: Data.Deallocator.none)
    let ciphertext = Data(bytesNoCopy: ciphertextPtr, count: Int(ciphertextLength), deallocator: Data.Deallocator.none)
    let aad = Data(bytesNoCopy: aadPtr, count: Int(aadLength), deallocator: Data.Deallocator.none)
    let tag = Data(bytesNoCopy: tagPtr, count: Int(tagLength), deallocator: Data.Deallocator.none)
    let symmetricKey = SymmetricKey(data: key)

    guard let nonce = try? ChaChaPoly.Nonce(data: nonceData) else {
        return 0
    }

    guard let sealedBox = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag) else {
        return 0
    }

    do {
        let result = try ChaChaPoly.open(sealedBox, using: symmetricKey, authenticating: aad)

        assert(plaintextBufferLength >= result.count)
        result.copyBytes(to: plaintextBuffer, count: result.count)
        return 1
    }
    catch CryptoKitError.authenticationFailure {
        return -1
    }
    catch {
        return 0
    }
}

@_cdecl("AppleCryptoNative_AesGcmEncrypt")
public func AppleCryptoNative_AesGcmEncrypt(
    keyPtr: UnsafeMutableRawPointer,
    keyLength: Int32,
    noncePtr: UnsafeMutableRawPointer,
    nonceLength: Int32,
    plaintextPtr: UnsafeMutableRawPointer,
    plaintextLength: Int32,
    ciphertextBuffer: UnsafeMutablePointer<UInt8>,
    ciphertextBufferLength: Int32,
    tagBuffer: UnsafeMutablePointer<UInt8>,
    tagBufferLength: Int32,
    aadPtr: UnsafeMutableRawPointer,
    aadLength: Int32
 ) -> Int32 {
    let nonceData = Data(bytesNoCopy: noncePtr, count: Int(nonceLength), deallocator: Data.Deallocator.none)
    let key = Data(bytesNoCopy: keyPtr, count: Int(keyLength), deallocator: Data.Deallocator.none)
    let plaintext = Data(bytesNoCopy: plaintextPtr, count: Int(plaintextLength), deallocator: Data.Deallocator.none)
    let aad = Data(bytesNoCopy: aadPtr, count: Int(aadLength), deallocator: Data.Deallocator.none)
    let symmetricKey = SymmetricKey(data: key)

    guard let nonce = try? AES.GCM.Nonce(data: nonceData) else {
        return 0
    }

    guard let result = try? AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: aad) else {
        return 0
    }

    assert(ciphertextBufferLength >= result.ciphertext.count)
    assert(tagBufferLength >= result.tag.count)

    result.ciphertext.copyBytes(to: ciphertextBuffer, count: result.ciphertext.count)
    result.tag.copyBytes(to: tagBuffer, count: result.tag.count)
    return 1
 }

@_cdecl("AppleCryptoNative_AesGcmDecrypt")
public func AppleCryptoNative_AesGcmDecrypt(
    keyPtr: UnsafeMutableRawPointer,
    keyLength: Int32,
    noncePtr: UnsafeMutableRawPointer,
    nonceLength: Int32,
    ciphertextPtr: UnsafeMutableRawPointer,
    ciphertextLength: Int32,
    tagPtr: UnsafeMutableRawPointer,
    tagLength: Int32,
    plaintextBuffer: UnsafeMutablePointer<UInt8>,
    plaintextBufferLength: Int32,
    aadPtr: UnsafeMutableRawPointer,
    aadLength: Int32
) -> Int32 {
    let nonceData = Data(bytesNoCopy: noncePtr, count: Int(nonceLength), deallocator: Data.Deallocator.none)
    let key = Data(bytesNoCopy: keyPtr, count: Int(keyLength), deallocator: Data.Deallocator.none)
    let ciphertext = Data(bytesNoCopy: ciphertextPtr, count: Int(ciphertextLength), deallocator: Data.Deallocator.none)
    let aad = Data(bytesNoCopy: aadPtr, count: Int(aadLength), deallocator: Data.Deallocator.none)
    let tag = Data(bytesNoCopy: tagPtr, count: Int(tagLength), deallocator: Data.Deallocator.none)
    let symmetricKey = SymmetricKey(data: key)

    guard let nonce = try? AES.GCM.Nonce(data: nonceData) else {
        return 0
    }

    guard let sealedBox = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag) else {
        return 0
    }

    do {
        let result = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)

        assert(plaintextBufferLength >= result.count)
        result.copyBytes(to: plaintextBuffer, count: result.count)
        return 1
    }
    catch CryptoKitError.authenticationFailure {
        return -1
    }
    catch {
        return 0
    }
}
