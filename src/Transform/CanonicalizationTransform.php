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

namespace XmlDSig\Transform;

use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Canonicalization\Canonicalizer;
use XmlDSig\Exception\TransformFailed;

final readonly class CanonicalizationTransform implements Transform
{
    /**
     * @param list<string> $inclusivePrefixes
     */
    public function __construct(
        private Canonicalizer $canonicalizer,
        private CanonicalizationAlgorithm $algorithm,
        private array $inclusivePrefixes = [],
    ) {
    }

    #[\Override]
    public function apply(TransformData $data, ?\DOMElement $signature): TransformData
    {
        if (!$data->isNodeSet()) {
            throw TransformFailed::because('canonicalization of octet streams is not supported.');
        }

        return TransformData::octets(
            $data->toOctets($this->canonicalizer, $this->algorithm, $this->inclusivePrefixes),
        );
    }
}
