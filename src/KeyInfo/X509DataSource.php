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

namespace XmlDSig\KeyInfo;

use XmlDSig\Key\X509Certificate;
use XmlDSig\Model\KeyInfo;

final readonly class X509DataSource implements KeyInfoSource
{
    /** @var list<X509Certificate> */
    private array $certificates;

    /**
     * @param X509Certificate $certificate Signing certificate, followed by optional chain certificates.
     */
    public function __construct(X509Certificate $certificate, X509Certificate ...$chain)
    {
        $this->certificates = [$certificate, ...\array_values($chain)];
    }

    #[\Override]
    public function keyInfo(): KeyInfo
    {
        return new KeyInfo(
            x509Certificates: \array_map(static fn (X509Certificate $c): string => $c->toDer(), $this->certificates),
        );
    }
}
