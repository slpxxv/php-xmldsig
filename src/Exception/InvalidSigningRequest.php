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

namespace XmlDSig\Exception;

final class InvalidSigningRequest extends \InvalidArgumentException implements XmlDSigException
{
    public static function noReferences(): self
    {
        return new self('A signature needs at least one reference.');
    }
}
