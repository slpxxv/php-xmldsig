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
use XmlDSig\Exception\VerificationFailed;
use XmlDSig\Key\PublicKey;
use XmlDSig\Model\KeyInfo;

/**
 * Supplies the trusted key a signature must verify against.
 *
 * ds:KeyInfo is attacker controlled: an implementation must never trust a key only because it is embedded.
 */
interface KeyResolver
{
    /**
     * @throws VerificationFailed
     */
    public function resolve(?KeyInfo $keyInfo, SignatureAlgorithm $algorithm): PublicKey;
}
