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

namespace XmlDSig\Verification\KeyResolver;

use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Key\PublicKey;
use XmlDSig\Model\KeyInfo;

/**
 * Always verifies with a key known up front; ds:KeyInfo is ignored.
 */
final readonly class StaticKeyResolver implements KeyResolver
{
    public function __construct(
        private PublicKey $key,
    ) {
    }

    #[\Override]
    public function resolve(?KeyInfo $keyInfo, SignatureAlgorithm $algorithm): PublicKey
    {
        return $this->key;
    }
}
