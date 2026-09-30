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

namespace XmlDSigTests\Verification\KeyResolver;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\KeyType;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\InvalidKey;
use XmlDSig\Exception\VerificationFailed;
use XmlDSig\Internal\SystemClock;
use XmlDSig\Key\X509Certificate;
use XmlDSig\Model\KeyInfo;
use XmlDSig\Verification\KeyResolver\PinnedCertificateResolver;
use XmlDSigTests\Fixtures\FrozenClock;
use XmlDSigTests\Fixtures\Keys;

#[CoversClass(PinnedCertificateResolver::class)]
#[CoversClass(X509Certificate::class)]
#[CoversClass(SystemClock::class)]
final class PinnedCertificateResolverTest extends TestCase
{
    public function testFindsPinnedCertificateAnywhereInChain(): void
    {
        $signer = $this->certificate(Keys::ecPrivatePem());
        $intermediate = $this->certificate(Keys::rsaPrivatePem());

        $key = (new PinnedCertificateResolver([$signer]))->resolve(
            new KeyInfo(x509Certificates: [$intermediate->toDer(), $signer->toDer()]),
            SignatureAlgorithm::EcdsaSha256,
        );

        self::assertSame(KeyType::Ec, $key->type);
    }

    public function testExpiredCertificateIsRejected(): void
    {
        $certificate = $this->certificate(Keys::rsaPrivatePem());
        $clock = new FrozenClock($certificate->validTo()->modify('+1 second'));

        $this->expectExceptionObject(VerificationFailed::certificateNotValid());

        (new PinnedCertificateResolver([$certificate], $clock))
            ->resolve(new KeyInfo(x509Certificates: [$certificate->toDer()]), SignatureAlgorithm::RsaSha256);
    }

    public function testNotYetValidCertificateIsRejected(): void
    {
        $certificate = $this->certificate(Keys::rsaPrivatePem());
        $clock = new FrozenClock($certificate->validFrom()->modify('-1 second'));

        $this->expectExceptionObject(VerificationFailed::certificateNotValid());

        (new PinnedCertificateResolver([$certificate], $clock))
            ->resolve(new KeyInfo(x509Certificates: [$certificate->toDer()]), SignatureAlgorithm::RsaSha256);
    }

    public function testMissingCertificateIsReported(): void
    {
        $this->expectExceptionObject(VerificationFailed::keyNotFound());

        (new PinnedCertificateResolver([$this->certificate(Keys::rsaPrivatePem())]))
            ->resolve(new KeyInfo(x509Certificates: ['not a certificate']), SignatureAlgorithm::RsaSha256);
    }

    public function testRequiresPinnedCertificate(): void
    {
        $this->expectException(InvalidKey::class);

        new PinnedCertificateResolver([]);
    }

    private function certificate(string $privatePem): X509Certificate
    {
        return X509Certificate::fromPem(Keys::certificatePem($privatePem));
    }
}
