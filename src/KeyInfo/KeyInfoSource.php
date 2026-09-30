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

/**
 * Describes how the verifier can find the key: embedded certificates, a key name, etc.
 */
interface KeyInfoSource
{
    public function keyInfo(): KeyInfo;
}
