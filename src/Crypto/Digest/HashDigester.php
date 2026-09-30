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

namespace XmlDSig\Crypto\Digest;

use XmlDSig\Algorithm\DigestAlgorithm;

final class HashDigester implements Digester
{
    #[\Override]
    public function digest(string $data, DigestAlgorithm $algorithm): string
    {
        return \hash($algorithm->hashName(), $data, true);
    }
}
