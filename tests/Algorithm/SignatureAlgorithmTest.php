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
use XmlDSig\Algorithm\DigestAlgorithm;
use XmlDSig\Algorithm\KeyType;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\UnsupportedAlgorithm;

#[CoversClass(SignatureAlgorithm::class)]
#[CoversClass(DigestAlgorithm::class)]
#[CoversClass(UnsupportedAlgorithm::class)]
final class SignatureAlgorithmTest extends TestCase
{
    public function testDigestFollowsSignatureAlgorithm(): void
    {
        self::assertSame(DigestAlgorithm::Sha256, SignatureAlgorithm::RsaSha256->digest());
        self::assertSame(DigestAlgorithm::Sha512, SignatureAlgorithm::EcdsaSha512->digest());
    }

    public function testKeyType(): void
    {
        self::assertSame(KeyType::Rsa, SignatureAlgorithm::RsaSha1->keyType());
        self::assertSame(KeyType::Ec, SignatureAlgorithm::EcdsaSha384->keyType());
    }

    public function testEveryDigestHasHashImplementation(): void
    {
        foreach (DigestAlgorithm::cases() as $digest) {
            self::assertContains($digest->hashName(), \hash_algos());
        }
    }

    public function testUnknownUriIsRejected(): void
    {
        $this->expectException(UnsupportedAlgorithm::class);

        SignatureAlgorithm::fromUri('urn:unknown');
    }
}
