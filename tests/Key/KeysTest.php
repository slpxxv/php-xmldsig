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

namespace XmlDSigTests\Key;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\KeyType;
use XmlDSig\Exception\InvalidKey;
use XmlDSig\Internal\OpenSsl;
use XmlDSig\Key\PrivateKey;
use XmlDSig\Key\PublicKey;
use XmlDSig\Key\X509Certificate;
use XmlDSigTests\Fixtures\Keys;

#[CoversClass(PrivateKey::class)]
#[CoversClass(PublicKey::class)]
#[CoversClass(X509Certificate::class)]
#[CoversClass(OpenSsl::class)]
#[CoversClass(InvalidKey::class)]
final class KeysTest extends TestCase
{
    public function testDetectsKeyTypes(): void
    {
        self::assertSame(KeyType::Rsa, PrivateKey::fromPem(Keys::rsaPrivatePem())->type);
        self::assertSame(KeyType::Ec, PrivateKey::fromPem(Keys::ecPrivatePem())->type);
    }

    public function testReadsEncryptedKey(): void
    {
        $key = PrivateKey::fromPem(Keys::rsaPrivatePem('secret'), 'secret');

        self::assertSame(2048, $key->bits);
    }

    public function testRejectsWrongPassphrase(): void
    {
        $this->expectException(InvalidKey::class);

        PrivateKey::fromPem(Keys::rsaPrivatePem('secret'), 'wrong');
    }

    public function testRejectsMissingFile(): void
    {
        $this->expectException(InvalidKey::class);

        PrivateKey::fromFile('/nonexistent/key.pem');
    }

    public function testCertificateRoundTripsThroughDer(): void
    {
        $certificate = X509Certificate::fromPem(Keys::certificatePem(Keys::rsaPrivatePem()));

        self::assertTrue($certificate->equals(X509Certificate::fromDer($certificate->toDer())));
    }

    public function testCertificateExposesPublicKey(): void
    {
        $certificate = X509Certificate::fromPem(Keys::certificatePem(Keys::ecPrivatePem()));

        self::assertSame(KeyType::Ec, $certificate->publicKey()->type);
    }

    public function testDerivesPublicKey(): void
    {
        self::assertSame(KeyType::Rsa, PrivateKey::fromPem(Keys::rsaPrivatePem())->publicKey()->type);
    }
}
