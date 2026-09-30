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

namespace XmlDSig\Exception;

final class VerificationFailed extends \RuntimeException implements XmlDSigException
{
    public static function signatureNotFound(): self
    {
        return new self('The document contains no ds:Signature.');
    }

    public static function ambiguousSignature(int $count): self
    {
        return new self(\sprintf('The document contains %d ds:Signature elements, pass the one to verify.', $count));
    }

    public static function foreignSignature(): self
    {
        return new self('The ds:Signature element does not belong to the verified document.');
    }

    public static function invalidSignatureValue(): self
    {
        return new self('The signature value does not match ds:SignedInfo.');
    }

    public static function digestMismatch(string $uri): self
    {
        return new self(\sprintf('Digest mismatch for reference "%s".', $uri));
    }

    public static function keyNotFound(): self
    {
        return new self('No verification key could be resolved from ds:KeyInfo.');
    }

    public static function untrustedKey(): self
    {
        return new self('The key provided in ds:KeyInfo is not trusted.');
    }

    public static function keyAlgorithmMismatch(): self
    {
        return new self('The verification key does not match the signature algorithm.');
    }
}
