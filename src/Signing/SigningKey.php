<?php

/*
 * This file is part of the slpxxv/php-xmldsig.
 *
 * Copyright (C) 2023 Dominik Szamburski
 *
 * This software may be modified and distributed under the terms
 * of the MIT license. See the LICENSE file for details.
 */

declare(strict_types=1);

namespace XmlDSig\Signing;

use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\KeyAlgorithmMismatch;
use XmlDSig\Key\PrivateKey;

/**
 * A private key bound to the one algorithm it signs with.
 */
final readonly class SigningKey
{
    /**
     * @throws KeyAlgorithmMismatch
     */
    public function __construct(
        public PrivateKey $key,
        public SignatureAlgorithm $algorithm,
    ) {
        if ($key->type !== $algorithm->keyType()) {
            throw KeyAlgorithmMismatch::for($key->type, $algorithm);
        }
    }
}
