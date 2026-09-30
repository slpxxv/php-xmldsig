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

namespace XmlDSig\Verification\KeyResolver;

use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\InvalidKey;
use XmlDSig\Exception\VerificationFailed;
use XmlDSig\Key\PublicKey;
use XmlDSig\Key\X509Certificate;
use XmlDSig\Model\KeyInfo;

/**
 * Accepts the certificate embedded in ds:X509Data only if it is one of the pinned certificates.
 *
 * Chain building and revocation are out of scope; implement KeyResolver for PKI validation.
 */
final readonly class PinnedCertificateResolver implements KeyResolver
{
    /** @var list<X509Certificate> */
    private array $trusted;

    public function __construct(X509Certificate $certificate, X509Certificate ...$more)
    {
        $this->trusted = [$certificate, ...\array_values($more)];
    }

    #[\Override]
    public function resolve(?KeyInfo $keyInfo, SignatureAlgorithm $algorithm): PublicKey
    {
        $der = $keyInfo?->x509Certificates[0] ?? throw VerificationFailed::keyNotFound();

        try {
            $certificate = X509Certificate::fromDer($der);
        } catch (InvalidKey) {
            throw VerificationFailed::keyNotFound();
        }

        foreach ($this->trusted as $trusted) {
            if ($trusted->equals($certificate)) {
                return $trusted->publicKey();
            }
        }

        throw VerificationFailed::untrustedKey();
    }
}
