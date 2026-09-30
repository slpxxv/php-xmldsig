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
use XmlDSig\Exception\UnsupportedAlgorithm;
use XmlDSig\Model\TransformSpec;

/**
 * Maps transform algorithm URIs to executable transforms.
 */
final readonly class TransformRegistry
{
    /**
     * @param array<string, \Closure(TransformSpec): Transform> $factories
     */
    public function __construct(
        private array $factories = [],
    ) {
    }

    public static function default(Canonicalizer $canonicalizer): self
    {
        $registry = (new self())->with(
            TransformSpec::ENVELOPED_SIGNATURE,
            static fn (): Transform => new EnvelopedSignatureTransform(),
        );

        foreach (CanonicalizationAlgorithm::cases() as $algorithm) {
            $registry = $registry->with(
                $algorithm->value,
                static fn (TransformSpec $spec): Transform => new CanonicalizationTransform(
                    $canonicalizer,
                    $algorithm,
                    $spec->inclusiveNamespaces,
                ),
            );
        }

        return $registry;
    }

    /**
     * @param \Closure(TransformSpec): Transform $factory
     */
    public function with(string $algorithm, \Closure $factory): self
    {
        return new self([...$this->factories, $algorithm => $factory]);
    }

    /**
     * @throws UnsupportedAlgorithm
     */
    public function create(TransformSpec $spec): Transform
    {
        $factory = $this->factories[$spec->algorithm] ?? throw UnsupportedAlgorithm::forUri($spec->algorithm);

        return $factory($spec);
    }
}
