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

namespace XmlDSig\Canonicalization;

use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Exception\TransformFailed;

interface Canonicalizer
{
    /**
     * @param list<string> $inclusivePrefixes InclusiveNamespaces PrefixList, exclusive C14N only.
     *
     * @throws TransformFailed
     */
    public function canonicalize(
        \DOMNode $node,
        CanonicalizationAlgorithm $algorithm,
        array $inclusivePrefixes = [],
    ): string;
}
