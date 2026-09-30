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

namespace XmlDSig\Reference;

use XmlDSig\Exception\DuplicateId;
use XmlDSig\Exception\ReferenceNotFound;

interface ReferenceResolver
{
    /**
     * @throws ReferenceNotFound
     * @throws DuplicateId
     */
    public function resolve(string $uri, \DOMDocument $document): \DOMNode;
}
