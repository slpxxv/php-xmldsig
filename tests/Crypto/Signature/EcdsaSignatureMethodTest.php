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
use PHPUnit\Framework\Attributes\DataProvider;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Crypto\Signature\EcdsaSignatureFormat;
use XmlDSig\Crypto\Signature\EcdsaSignatureMethod;
use XmlDSig\Crypto\Signature\SignatureMethod;
use XmlDSig\Key\PrivateKey;
use XmlDSigTests\Fixtures\Keys;

#[CoversClass(EcdsaSignatureMethod::class)]
#[CoversClass(EcdsaSignatureFormat::class)]
final class EcdsaSignatureMethodTest extends SignatureMethodContractTestCase
{
    /**
     * @return iterable<string, array{string, int, SignatureAlgorithm}>
     */
    public static function curves(): iterable
    {
        yield 'P-256' => ['prime256v1', 64, SignatureAlgorithm::EcdsaSha256];
        yield 'P-384' => ['secp384r1', 96, SignatureAlgorithm::EcdsaSha384];
        yield 'P-521' => ['secp521r1', 132, SignatureAlgorithm::EcdsaSha512];
    }

    #[DataProvider('curves')]
    public function testProducesFixedLengthRawSignature(string $curve, int $length, SignatureAlgorithm $algorithm): void
    {
        $key = PrivateKey::fromPem(Keys::ecPrivatePem($curve));

        for ($i = 0; $i < 20; $i++) {
            $signature = $this->method()->sign("payload-$i", $key, $algorithm);

            self::assertSame($length, \strlen($signature));
            self::assertTrue($this->method()->verify("payload-$i", $signature, $key->publicKey(), $algorithm));
        }
    }

    public function testRejectsMalformedDer(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        EcdsaSignatureFormat::derToRaw("\x30\x05\x02\x01\x01", 32);
    }

    #[\Override]
    protected function method(): SignatureMethod
    {
        return new EcdsaSignatureMethod();
    }

    #[\Override]
    protected function algorithm(): SignatureAlgorithm
    {
        return SignatureAlgorithm::EcdsaSha256;
    }

    #[\Override]
    protected function key(): PrivateKey
    {
        return PrivateKey::fromPem(Keys::ecPrivatePem());
    }

    #[\Override]
    protected function foreignKey(): PrivateKey
    {
        return PrivateKey::fromPem(Keys::rsaPrivatePem());
    }
}
