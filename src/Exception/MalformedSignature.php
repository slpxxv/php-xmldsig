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

final class MalformedSignature extends \RuntimeException implements XmlDSigException
{
    public static function because(string $reason): self
    {
        return new self('Malformed ds:Signature: ' . $reason);
    }
}
