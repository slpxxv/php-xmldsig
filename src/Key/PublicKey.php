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

final readonly class PublicKey
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
    public static function fromPem(string $pem): self
    {
        $key = \openssl_pkey_get_public($pem);
        if ($key === false) {
            throw InvalidKey::unreadable('public key', OpenSsl::lastError());
        }

        return self::fromHandle($key);
    }

    /**
     * @throws InvalidKey
     */
    public static function fromFile(string $path): self
    {
        return self::fromPem(OpenSsl::readFile($path));
    }

    /**
     * @internal
     */
    public static function fromHandle(\OpenSSLAsymmetricKey $key): self
    {
        return new self($key, OpenSsl::keyType($key), OpenSsl::keyBits($key));
    }

    /**
     * @internal
     */
    public function handle(): \OpenSSLAsymmetricKey
    {
        return $this->key;
    }
}
