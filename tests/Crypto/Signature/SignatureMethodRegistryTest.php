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

namespace XmlDSigTests\Crypto\Signature;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Crypto\Signature\EcdsaSignatureMethod;
use XmlDSig\Crypto\Signature\RsaSignatureMethod;
use XmlDSig\Crypto\Signature\SignatureMethodRegistry;
use XmlDSig\Exception\UnsupportedAlgorithm;

#[CoversClass(SignatureMethodRegistry::class)]
final class SignatureMethodRegistryTest extends TestCase
{
    public function testSelectsMethodByAlgorithm(): void
    {
        $registry = SignatureMethodRegistry::default();

        self::assertInstanceOf(RsaSignatureMethod::class, $registry->for(SignatureAlgorithm::RsaSha256));
        self::assertInstanceOf(EcdsaSignatureMethod::class, $registry->for(SignatureAlgorithm::EcdsaSha256));
    }

    public function testFailsForUnregisteredAlgorithm(): void
    {
        $this->expectException(UnsupportedAlgorithm::class);

        (new SignatureMethodRegistry(new RsaSignatureMethod()))->for(SignatureAlgorithm::EcdsaSha256);
    }
}
