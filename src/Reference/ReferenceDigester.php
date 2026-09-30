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

namespace XmlDSig\Reference;

use XmlDSig\Algorithm\DigestAlgorithm;
use XmlDSig\Crypto\Digest\Digester;
use XmlDSig\Model\TransformSpec;
use XmlDSig\Transform\TransformData;
use XmlDSig\Transform\TransformPipeline;

/**
 * Dereferences a URI, runs its transforms and digests the result.
 */
final readonly class ReferenceDigester
{
    public function __construct(
        private ReferenceResolver $resolver,
        private TransformPipeline $pipeline,
        private Digester $digester,
    ) {
    }

    /**
     * @param list<TransformSpec> $transforms
     */
    public function digest(
        \DOMDocument $document,
        string $uri,
        array $transforms,
        DigestAlgorithm $algorithm,
        ?\DOMElement $signature = null,
    ): ReferenceDigest {
        $node = $this->resolver->resolve($uri, $document);
        $octets = $this->pipeline->process(TransformData::nodeSet($node), $transforms, $signature);

        return new ReferenceDigest($node, $this->digester->digest($octets, $algorithm));
    }
}
