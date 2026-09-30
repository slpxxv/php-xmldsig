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

namespace XmlDSig\Model;

use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Algorithm\SignatureAlgorithm;

final readonly class SignedInfo
{
    /**
     * @param non-empty-list<Reference> $references
     * @param list<string> $inclusiveNamespaces ec:InclusiveNamespaces of the CanonicalizationMethod.
     */
    public function __construct(
        public CanonicalizationAlgorithm $canonicalization,
        public SignatureAlgorithm $signatureAlgorithm,
        public array $references,
        public array $inclusiveNamespaces = [],
    ) {
    }
}
