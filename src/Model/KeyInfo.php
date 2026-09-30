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

namespace XmlDSig\Model;

final readonly class KeyInfo
{
    /**
     * @param list<string> $x509Certificates DER encoded certificates.
     */
    public function __construct(
        public ?string $keyName = null,
        public array $x509Certificates = [],
    ) {
    }
}
