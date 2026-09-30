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

namespace XmlDSig\Signing;

use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Algorithm\DigestAlgorithm;
use XmlDSig\Model\TransformSpec;

/**
 * What to sign: the digest is computed by the signer.
 */
final readonly class ReferenceDefinition
{
    /**
     * @param list<TransformSpec> $transforms
     */
    public function __construct(
        public string $uri,
        public DigestAlgorithm $digestAlgorithm = DigestAlgorithm::Sha256,
        public array $transforms = [],
        public ?string $id = null,
        public ?string $type = null,
    ) {
    }

    /**
     * The usual reference for a signature placed inside the signed element.
     *
     * @param list<string> $inclusiveNamespaces
     */
    public static function enveloped(
        string $uri,
        DigestAlgorithm $digestAlgorithm = DigestAlgorithm::Sha256,
        CanonicalizationAlgorithm $canonicalization = CanonicalizationAlgorithm::Exclusive,
        array $inclusiveNamespaces = [],
    ): self {
        return new self($uri, $digestAlgorithm, [
            TransformSpec::envelopedSignature(),
            TransformSpec::canonicalization($canonicalization, $inclusiveNamespaces),
        ]);
    }
}
