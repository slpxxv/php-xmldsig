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

namespace XmlDSig\Algorithm;

use XmlDSig\Exception\AlgorithmNotAllowed;

/**
 * Decides which algorithms may be used for signing and accepted during verification.
 */
final readonly class AlgorithmPolicy
{
    /**
     * @param list<SignatureAlgorithm> $signatureAlgorithms
     * @param list<DigestAlgorithm> $digestAlgorithms
     */
    public function __construct(
        private array $signatureAlgorithms,
        private array $digestAlgorithms,
    ) {
    }

    /**
     * Everything except SHA-1 based algorithms.
     */
    public static function secure(): self
    {
        return new self(
            \array_values(\array_filter(
                SignatureAlgorithm::cases(),
                static fn (SignatureAlgorithm $a): bool => $a->digest() !== DigestAlgorithm::Sha1,
            )),
            \array_values(\array_filter(
                DigestAlgorithm::cases(),
                static fn (DigestAlgorithm $a): bool => $a !== DigestAlgorithm::Sha1,
            )),
        );
    }

    /**
     * Every supported algorithm, including SHA-1. Use only for legacy interoperability.
     */
    public static function legacy(): self
    {
        return new self(SignatureAlgorithm::cases(), DigestAlgorithm::cases());
    }

    /**
     * @throws AlgorithmNotAllowed
     */
    public function assertSignatureAllowed(SignatureAlgorithm $algorithm): void
    {
        if (!\in_array($algorithm, $this->signatureAlgorithms, true)) {
            throw AlgorithmNotAllowed::forUri($algorithm->value);
        }
    }

    /**
     * @throws AlgorithmNotAllowed
     */
    public function assertDigestAllowed(DigestAlgorithm $algorithm): void
    {
        if (!\in_array($algorithm, $this->digestAlgorithms, true)) {
            throw AlgorithmNotAllowed::forUri($algorithm->value);
        }
    }
}
