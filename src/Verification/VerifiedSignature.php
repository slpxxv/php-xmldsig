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

namespace XmlDSig\Verification;

use XmlDSig\Key\PublicKey;
use XmlDSig\Model\Signature;

final readonly class VerifiedSignature
{
    /**
     * @param list<\DOMNode> $signedNodes Nodes the references resolved to.
     */
    public function __construct(
        public Signature $signature,
        public array $signedNodes,
        public PublicKey $key,
    ) {
    }

    /**
     * Whether the node is covered by the signature. Always check the node you actually
     * consume: a valid signature elsewhere in the document proves nothing about it.
     */
    public function covers(\DOMNode $node): bool
    {
        for ($current = $node; $current !== null; $current = $current->parentNode) {
            foreach ($this->signedNodes as $signed) {
                if ($current->isSameNode($signed)) {
                    return true;
                }
            }
        }

        return false;
    }
}
