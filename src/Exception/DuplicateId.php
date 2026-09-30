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

/**
 * Raised when an ID is ambiguous, a typical sign of a signature wrapping attack.
 */
final class DuplicateId extends \RuntimeException implements XmlDSigException
{
    public static function forId(string $id): self
    {
        return new self(\sprintf('ID "%s" is used by more than one element.', $id));
    }
}
