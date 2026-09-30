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

namespace XmlDSigTests\Crypto\Digest;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\DigestAlgorithm;
use XmlDSig\Crypto\Digest\HashDigester;

#[CoversClass(HashDigester::class)]
final class HashDigesterTest extends TestCase
{
    public function testReturnsRawDigest(): void
    {
        self::assertSame(
            \hex2bin('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
            (new HashDigester())->digest('abc', DigestAlgorithm::Sha256),
        );
    }
}
