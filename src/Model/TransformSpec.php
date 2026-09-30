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

use XmlDSig\Algorithm\CanonicalizationAlgorithm;

/**
 * The ds:Transform element: an algorithm URI and its parameters.
 */
final readonly class TransformSpec
{
    public const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /**
     * @param list<string> $inclusiveNamespaces ec:InclusiveNamespaces PrefixList.
     */
    public function __construct(
        public string $algorithm,
        public array $inclusiveNamespaces = [],
    ) {
    }

    public static function envelopedSignature(): self
    {
        return new self(self::ENVELOPED_SIGNATURE);
    }

    /**
     * @param list<string> $inclusiveNamespaces
     */
    public static function canonicalization(
        CanonicalizationAlgorithm $algorithm,
        array $inclusiveNamespaces = [],
    ): self {
        return new self($algorithm->value, $algorithm->isExclusive() ? $inclusiveNamespaces : []);
    }
}
