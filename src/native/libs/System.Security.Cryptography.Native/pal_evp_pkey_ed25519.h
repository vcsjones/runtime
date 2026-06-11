// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "opensslshim.h"
#include "pal_compiler.h"
#include "pal_types.h"

/*
Determines if the Ed25519 algorithm is supported.

Returns 1 if the algorithm is available, 0 otherwise.
*/
PALEXPORT int32_t CryptoNative_Ed25519Available(void);

/*
Exports the raw private key material from an Ed25519 EVP_PKEY.

Returns 1 on success, 0 on failure, -1 if the exported key length does not match destinationLength.
*/
PALEXPORT int32_t CryptoNative_Ed25519ExportPrivateKey(const EVP_PKEY* key, uint8_t* destination, int32_t destinationLength);

/*
Exports the raw public key material from an Ed25519 EVP_PKEY.

Returns 1 on success, 0 on failure, -1 if the exported key length does not match destinationLength.
*/
PALEXPORT int32_t CryptoNative_Ed25519ExportPublicKey(const EVP_PKEY* key, uint8_t* destination, int32_t destinationLength);

/*
Generates a new Ed25519 key pair and returns it as an EVP_PKEY.

Returns the new EVP_PKEY on success, NULL on failure.
*/
PALEXPORT EVP_PKEY* CryptoNative_Ed25519GenerateKey(void);

/*
Imports a raw private key and returns a new Ed25519 EVP_PKEY.

Returns the new EVP_PKEY on success, NULL on failure.
*/
PALEXPORT EVP_PKEY* CryptoNative_Ed25519ImportPrivateKey(const uint8_t* source, int32_t sourceLength);

/*
Imports a raw public key and returns a new Ed25519 EVP_PKEY.

Returns the new EVP_PKEY on success, NULL on failure.
*/
PALEXPORT EVP_PKEY* CryptoNative_Ed25519ImportPublicKey(const uint8_t* source, int32_t sourceLength);

/*
Signs data with an Ed25519 EVP_PKEY.

Returns 1 on success, 0 on failure, -1 if the signature length does not match destinationLength.
*/
PALEXPORT int32_t CryptoNative_Ed25519SignData(
    EVP_PKEY* key, const uint8_t* data, int32_t dataLength, uint8_t* destination, int32_t destinationLength);

/*
Verifies data with an Ed25519 EVP_PKEY.

Returns 1 if the signature is valid, 0 if the signature is invalid, -1 on failure.
*/
PALEXPORT int32_t CryptoNative_Ed25519VerifyData(
    EVP_PKEY* key, const uint8_t* data, int32_t dataLength, const uint8_t* signature, int32_t signatureLength);
