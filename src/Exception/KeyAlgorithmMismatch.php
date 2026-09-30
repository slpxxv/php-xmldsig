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

use XmlDSig\Algorithm\KeyType;
use XmlDSig\Algorithm\SignatureAlgorithm;

final class KeyAlgorithmMismatch extends \InvalidArgumentException implements XmlDSigException
{
    public static function for(KeyType $keyType, SignatureAlgorithm $algorithm): self
    {
        return new self(\sprintf('A %s key cannot be used with "%s".', $keyType->name, $algorithm->value));
    }
}
