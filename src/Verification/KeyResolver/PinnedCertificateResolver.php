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

namespace XmlDSig\Verification\KeyResolver;

use Psr\Clock\ClockInterface;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\InvalidKey;
use XmlDSig\Exception\VerificationFailed;
use XmlDSig\Internal\SystemClock;
use XmlDSig\Key\PublicKey;
use XmlDSig\Key\X509Certificate;
use XmlDSig\Model\KeyInfo;

/**
 * Accepts a certificate embedded in ds:X509Data only if it is pinned and currently valid.
 *
 * Chain building and revocation are out of scope; implement KeyResolver for PKI validation.
 */
final readonly class PinnedCertificateResolver implements KeyResolver
{
    /** @var non-empty-list<X509Certificate> */
    private array $trusted;

    /**
     * @param list<X509Certificate> $trusted
     *
     * @throws InvalidKey when no certificate is pinned.
     */
    public function __construct(
        array $trusted,
        private ClockInterface $clock = new SystemClock(),
    ) {
        if ($trusted === []) {
            throw InvalidKey::noTrustedCertificates();
        }
        $this->trusted = $trusted;
    }

    #[\Override]
    public function resolve(?KeyInfo $keyInfo, SignatureAlgorithm $algorithm): PublicKey
    {
        // X509Data may carry the chain in any order, so every certificate is a candidate.
        $found = false;
        foreach ($keyInfo?->x509Certificates ?? [] as $der) {
            try {
                $candidate = X509Certificate::fromDer($der);
            } catch (InvalidKey) {
                continue;
            }
            $found = true;

            $trusted = $this->pinned($candidate);
            if ($trusted === null) {
                continue;
            }
            if (!$trusted->isValidAt($this->clock->now())) {
                throw VerificationFailed::certificateNotValid();
            }

            return $trusted->publicKey();
        }

        throw $found ? VerificationFailed::untrustedKey() : VerificationFailed::keyNotFound();
    }

    private function pinned(X509Certificate $candidate): ?X509Certificate
    {
        foreach ($this->trusted as $trusted) {
            if ($trusted->equals($candidate)) {
                return $trusted;
            }
        }

        return null;
    }
}
