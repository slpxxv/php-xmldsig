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

final class ReferenceNotFound extends \RuntimeException implements XmlDSigException
{
    public static function forId(string $id): self
    {
        return new self(\sprintf('No element with ID "%s" found.', $id));
    }

    public static function unsupportedUri(string $uri): self
    {
        return new self(\sprintf('Reference URI "%s" is not supported, only same-document references are.', $uri));
    }
}
