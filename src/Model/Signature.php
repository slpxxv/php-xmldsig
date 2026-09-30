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

final readonly class Signature
{
    /**
     * @param string $signatureValue Raw binary signature value, empty until signed.
     */
    public function __construct(
        public SignedInfo $signedInfo,
        public string $signatureValue = '',
        public ?KeyInfo $keyInfo = null,
        public ?string $id = null,
    ) {
    }
}
