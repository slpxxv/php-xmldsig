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

namespace XmlDSig\Canonicalization;

use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Exception\TransformFailed;

final class DomCanonicalizer implements Canonicalizer
{
    #[\Override]
    public function canonicalize(
        \DOMNode $node,
        CanonicalizationAlgorithm $algorithm,
        array $inclusivePrefixes = [],
    ): string {
        $prefixes = $algorithm->isExclusive() && $inclusivePrefixes !== [] ? $inclusivePrefixes : null;

        $result = $node->C14N($algorithm->isExclusive(), $algorithm->withComments(), null, $prefixes);
        if ($result === false) {
            throw TransformFailed::because(\sprintf('cannot canonicalize using "%s".', $algorithm->value));
        }

        return $result;
    }
}
