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

namespace XmlDSigTests\Fixtures;

use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Crypto\Signature\SignatureMethod;
use XmlDSig\Exception\SigningFailed;
use XmlDSig\Key\PrivateKey;
use XmlDSig\Key\PublicKey;

final class FailingSignatureMethod implements SignatureMethod
{
    #[\Override]
    public function supports(SignatureAlgorithm $algorithm): bool
    {
        return true;
    }

    #[\Override]
    public function sign(string $data, PrivateKey $key, SignatureAlgorithm $algorithm): string
    {
        throw SigningFailed::because('HSM unavailable');
    }

    #[\Override]
    public function verify(string $data, string $signature, PublicKey $key, SignatureAlgorithm $algorithm): bool
    {
        return false;
    }
}
