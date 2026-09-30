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

namespace XmlDSig\Signing;

use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Exception\InvalidSigningRequest;
use XmlDSig\KeyInfo\KeyInfoSource;
use XmlDSig\Signing\Placement\SignaturePlacement;

final readonly class SigningRequest
{
    /** @var non-empty-list<ReferenceDefinition> */
    public array $references;

    /**
     * @param list<ReferenceDefinition> $references
     *
     * @throws InvalidSigningRequest
     */
    public function __construct(
        public SigningKey $signingKey,
        array $references,
        public SignaturePlacement $placement,
        public CanonicalizationAlgorithm $canonicalization = CanonicalizationAlgorithm::Exclusive,
        public ?KeyInfoSource $keyInfo = null,
        public ?string $signatureId = null,
    ) {
        if ($references === []) {
            throw InvalidSigningRequest::noReferences();
        }
        $this->references = $references;
    }
}
