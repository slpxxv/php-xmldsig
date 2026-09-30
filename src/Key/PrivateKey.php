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

namespace XmlDSig\Key;

use XmlDSig\Algorithm\KeyType;
use XmlDSig\Exception\InvalidKey;
use XmlDSig\Internal\OpenSsl;

final readonly class PrivateKey
{
    private function __construct(
        private \OpenSSLAsymmetricKey $key,
        public KeyType $type,
        public int $bits,
    ) {
    }

    /**
     * @throws InvalidKey
     */
    public static function fromPem(string $pem, ?string $passphrase = null): self
    {
        $key = \openssl_pkey_get_private($pem, $passphrase);
        if ($key === false) {
            throw InvalidKey::unreadable('private key', OpenSsl::lastError());
        }

        return new self($key, OpenSsl::keyType($key), OpenSsl::keyBits($key));
    }

    /**
     * @throws InvalidKey
     */
    public static function fromFile(string $path, ?string $passphrase = null): self
    {
        return self::fromPem(OpenSsl::readFile($path), $passphrase);
    }

    public function publicKey(): PublicKey
    {
        $details = \openssl_pkey_get_details($this->key);
        $pem = $details === false ? null : ($details['key'] ?? null);
        if (!\is_string($pem)) {
            throw InvalidKey::unreadable('public part of the private key', OpenSsl::lastError());
        }

        return PublicKey::fromPem($pem);
    }

    /**
     * @internal
     */
    public function handle(): \OpenSSLAsymmetricKey
    {
        return $this->key;
    }
}
