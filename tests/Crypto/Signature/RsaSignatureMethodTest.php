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

namespace XmlDSigTests\Crypto\Signature;

use PHPUnit\Framework\Attributes\CoversClass;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Crypto\Signature\RsaSignatureMethod;
use XmlDSig\Crypto\Signature\SignatureMethod;
use XmlDSig\Key\PrivateKey;
use XmlDSigTests\Fixtures\Keys;

#[CoversClass(RsaSignatureMethod::class)]
final class RsaSignatureMethodTest extends SignatureMethodContractTestCase
{
    public function testDigestFollowsAlgorithm(): void
    {
        $signature = $this->method()->sign('payload', $this->key(), SignatureAlgorithm::RsaSha512);

        self::assertSame(1, \openssl_verify('payload', $signature, $this->key()->publicKey()->handle(), 'sha512'));
    }

    #[\Override]
    protected function method(): SignatureMethod
    {
        return new RsaSignatureMethod();
    }

    #[\Override]
    protected function algorithm(): SignatureAlgorithm
    {
        return SignatureAlgorithm::RsaSha256;
    }

    #[\Override]
    protected function key(): PrivateKey
    {
        return PrivateKey::fromPem(Keys::rsaPrivatePem());
    }

    #[\Override]
    protected function foreignKey(): PrivateKey
    {
        return PrivateKey::fromPem(Keys::ecPrivatePem());
    }
}
