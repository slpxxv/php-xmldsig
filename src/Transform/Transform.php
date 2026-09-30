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

namespace XmlDSig\Transform;

use XmlDSig\Exception\TransformFailed;

interface Transform
{
    /**
     * @param \DOMElement|null $signature The ds:Signature being processed, null while it is not yet in the document.
     *
     * @throws TransformFailed
     */
    public function apply(TransformData $data, ?\DOMElement $signature): TransformData;
}
