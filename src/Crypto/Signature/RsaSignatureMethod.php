<?php

/*
 * This file is part of the sxbrsky/xmldsig.
 *
 * Copyright (C) 2023 Dominik Szamburski
 *
 * This software may be modified and distributed under the terms
 * of the MIT license. See the LICENSE file for details.
 */

declare(strict_types=1);

namespace XmlDSig\Crypto\Signature;

use XmlDSig\Algorithm\KeyType;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\KeyAlgorithmMismatch;
use XmlDSig\Exception\SigningFailed;
use XmlDSig\Internal\OpenSsl;
use XmlDSig\Key\PrivateKey;
use XmlDSig\Key\PublicKey;

/**
 * RSASSA-PKCS1-v1_5 (RFC 6931).
 */
final class RsaSignatureMethod implements SignatureMethod
{
    #[\Override]
    public function supports(SignatureAlgorithm $algorithm): bool
    {
        return $algorithm->keyType() === KeyType::Rsa;
    }

    #[\Override]
    public function sign(string $data, PrivateKey $key, SignatureAlgorithm $algorithm): string
    {
        $this->assertKeyType($key->type, $algorithm);

        if (!\openssl_sign($data, $signature, $key->handle(), $algorithm->digest()->hashName())) {
            throw SigningFailed::because(OpenSsl::lastError());
        }

        return $signature;
    }

    #[\Override]
    public function verify(string $data, string $signature, PublicKey $key, SignatureAlgorithm $algorithm): bool
    {
        $this->assertKeyType($key->type, $algorithm);

        $result = \openssl_verify($data, $signature, $key->handle(), $algorithm->digest()->hashName());
        if ($result !== 1) {
            OpenSsl::lastError();
        }

        return $result === 1;
    }

    private function assertKeyType(KeyType $type, SignatureAlgorithm $algorithm): void
    {
        if ($type !== KeyType::Rsa || !$this->supports($algorithm)) {
            throw KeyAlgorithmMismatch::for($type, $algorithm);
        }
    }
}
