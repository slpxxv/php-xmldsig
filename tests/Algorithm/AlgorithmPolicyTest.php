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

namespace XmlDSigTests\Algorithm;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\AlgorithmPolicy;
use XmlDSig\Algorithm\DigestAlgorithm;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\AlgorithmNotAllowed;

#[CoversClass(AlgorithmPolicy::class)]
#[CoversClass(AlgorithmNotAllowed::class)]
final class AlgorithmPolicyTest extends TestCase
{
    public function testSecurePolicyRejectsSha1Signature(): void
    {
        $this->expectException(AlgorithmNotAllowed::class);

        AlgorithmPolicy::secure()->assertSignatureAllowed(SignatureAlgorithm::RsaSha1);
    }

    public function testSecurePolicyRejectsSha1Digest(): void
    {
        $this->expectException(AlgorithmNotAllowed::class);

        AlgorithmPolicy::secure()->assertDigestAllowed(DigestAlgorithm::Sha1);
    }

    public function testLegacyPolicyAllowsSha1(): void
    {
        $this->expectNotToPerformAssertions();

        AlgorithmPolicy::legacy()->assertSignatureAllowed(SignatureAlgorithm::RsaSha1);
        AlgorithmPolicy::legacy()->assertDigestAllowed(DigestAlgorithm::Sha1);
    }

    public function testSecurePolicyAllowsSha256(): void
    {
        $this->expectNotToPerformAssertions();

        AlgorithmPolicy::secure()->assertSignatureAllowed(SignatureAlgorithm::EcdsaSha256);
        AlgorithmPolicy::secure()->assertDigestAllowed(DigestAlgorithm::Sha256);
    }
}
