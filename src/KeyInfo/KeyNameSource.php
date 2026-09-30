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

namespace XmlDSig\KeyInfo;

use XmlDSig\Model\KeyInfo;

final readonly class KeyNameSource implements KeyInfoSource
{
    public function __construct(
        private string $keyName,
    ) {
    }

    #[\Override]
    public function keyInfo(): KeyInfo
    {
        return new KeyInfo(keyName: $this->keyName);
    }
}
