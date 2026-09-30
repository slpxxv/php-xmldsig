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

namespace XmlDSig\Signing\Placement;

/**
 * Places the signature right after a sibling, e.g. after saml:Issuer.
 */
final readonly class InsertAfter implements SignaturePlacement
{
    public function __construct(
        private \DOMElement $sibling,
    ) {
    }

    #[\Override]
    public function place(\DOMElement $signature): void
    {
        $parent = $this->sibling->parentNode ?? throw new \LogicException('The sibling element has no parent.');
        $parent->insertBefore($signature, $this->sibling->nextSibling);
    }
}
