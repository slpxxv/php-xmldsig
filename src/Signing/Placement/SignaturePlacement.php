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

namespace XmlDSig\Signing\Placement;

/**
 * Decides where the ds:Signature element goes in the document.
 */
interface SignaturePlacement
{
    public function place(\DOMElement $signature): void;
}
