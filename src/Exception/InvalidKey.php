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

final class InvalidKey extends \InvalidArgumentException implements XmlDSigException
{
    public static function unreadable(string $what, string $reason): self
    {
        return new self(\sprintf('Cannot read the %s: %s', $what, $reason));
    }

    public static function fileNotReadable(string $path): self
    {
        return new self(\sprintf('The file "%s" does not exist or is not readable.', $path));
    }

    public static function unsupportedType(): self
    {
        return new self('Only RSA and EC keys are supported.');
    }
}
