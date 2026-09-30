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

namespace XmlDSig\Crypto\Signature;

use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\UnsupportedAlgorithm;

final readonly class SignatureMethodRegistry
{
    /** @var list<SignatureMethod> */
    private array $methods;

    public function __construct(SignatureMethod ...$methods)
    {
        $this->methods = \array_values($methods);
    }

    public static function default(): self
    {
        return new self(new RsaSignatureMethod(), new EcdsaSignatureMethod());
    }

    /**
     * @throws UnsupportedAlgorithm
     */
    public function for(SignatureAlgorithm $algorithm): SignatureMethod
    {
        foreach ($this->methods as $method) {
            if ($method->supports($algorithm)) {
                return $method;
            }
        }

        throw UnsupportedAlgorithm::forUri($algorithm->value);
    }
}
