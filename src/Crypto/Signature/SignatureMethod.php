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

namespace XmlDSig\Crypto\Signature;

use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\KeyAlgorithmMismatch;
use XmlDSig\Exception\SigningFailed;
use XmlDSig\Key\PrivateKey;
use XmlDSig\Key\PublicKey;

/**
 * A family of signature algorithms, producing values in the XMLDSig wire format.
 */
interface SignatureMethod
{
    public function supports(SignatureAlgorithm $algorithm): bool;

    /**
     * @throws KeyAlgorithmMismatch
     * @throws SigningFailed
     */
    public function sign(string $data, PrivateKey $key, SignatureAlgorithm $algorithm): string;

    /**
     * @throws KeyAlgorithmMismatch
     */
    public function verify(string $data, string $signature, PublicKey $key, SignatureAlgorithm $algorithm): bool;
}
