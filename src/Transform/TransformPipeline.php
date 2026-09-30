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

namespace XmlDSig\Transform;

use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Canonicalization\Canonicalizer;
use XmlDSig\Exception\TransformFailed;
use XmlDSig\Exception\UnsupportedAlgorithm;
use XmlDSig\Model\TransformSpec;

final readonly class TransformPipeline
{
    public function __construct(
        private TransformRegistry $registry,
        private Canonicalizer $canonicalizer,
    ) {
    }

    /**
     * Applies the transforms and returns the octets to be digested.
     *
     * @param list<TransformSpec> $transforms
     *
     * @throws TransformFailed
     * @throws UnsupportedAlgorithm
     */
    public function process(TransformData $data, array $transforms, ?\DOMElement $signature): string
    {
        foreach ($transforms as $spec) {
            $data = $this->registry->create($spec)->apply($data, $signature);
        }

        // A remaining node-set is converted with inclusive C14N (XMLDSig 4.4.3.2).
        return $data->toOctets($this->canonicalizer, CanonicalizationAlgorithm::Inclusive);
    }
}
