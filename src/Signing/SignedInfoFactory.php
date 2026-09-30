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

use XmlDSig\Model\Reference;
use XmlDSig\Model\SignedInfo;
use XmlDSig\Reference\ReferenceDigester;

final readonly class SignedInfoFactory
{
    public function __construct(
        private ReferenceDigester $digester,
    ) {
    }

    /**
     * Digests every reference. Must run before the signature is placed in the document.
     */
    public function create(\DOMDocument $document, SigningRequest $request): SignedInfo
    {
        $references = \array_map(
            fn (ReferenceDefinition $definition): Reference => new Reference(
                $definition->uri,
                $definition->digestAlgorithm,
                $this->digester->digest(
                    $document,
                    $definition->uri,
                    $definition->transforms,
                    $definition->digestAlgorithm,
                )->digest,
                $definition->transforms,
                $definition->id,
                $definition->type,
            ),
            $request->references,
        );

        return new SignedInfo(
            $request->canonicalization,
            $request->signingKey->algorithm,
            $references,
            $request->canonicalization->isExclusive() ? $request->inclusiveNamespaces : [],
        );
    }
}
