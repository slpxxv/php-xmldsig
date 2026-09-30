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

namespace XmlDSig\Transform;

use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Canonicalization\Canonicalizer;

/**
 * Input and output of a transform: either an XPath-like node-set or octets.
 *
 * A node-set is modelled as a subtree root minus excluded subtrees; comments are
 * never part of it, as same-document references strip them (XMLDSig 4.4.3.3).
 */
final readonly class TransformData
{
    /**
     * @param list<\DOMNode> $excluded
     */
    private function __construct(
        public ?\DOMNode $root,
        public array $excluded,
        public ?string $octets,
    ) {
    }

    public static function nodeSet(\DOMNode $root): self
    {
        return new self($root, [], null);
    }

    public static function octets(string $octets): self
    {
        return new self(null, [], $octets);
    }

    public function isNodeSet(): bool
    {
        return $this->root !== null;
    }

    public function excluding(\DOMNode $node): self
    {
        return new self($this->root, [...$this->excluded, $node], $this->octets);
    }

    /**
     * @param list<string> $inclusivePrefixes
     */
    public function toOctets(
        Canonicalizer $canonicalizer,
        CanonicalizationAlgorithm $algorithm,
        array $inclusivePrefixes = [],
    ): string {
        if ($this->root === null) {
            return (string) $this->octets;
        }

        // Detaching keeps ancestors' namespace context intact, which cloning would lose.
        $restore = [];
        foreach ($this->excluded as $node) {
            $parent = $node->parentNode;
            if ($parent !== null && $this->isInsideRoot($node, $this->root)) {
                $restore[] = [$node, $parent, $node->nextSibling];
                $parent->removeChild($node);
            }
        }

        try {
            return $canonicalizer->canonicalize($this->root, $algorithm->withoutComments(), $inclusivePrefixes);
        } finally {
            foreach (\array_reverse($restore) as [$node, $parent, $next]) {
                $parent->insertBefore($node, $next);
            }
        }
    }

    private function isInsideRoot(\DOMNode $node, \DOMNode $root): bool
    {
        for ($current = $node->parentNode; $current !== null; $current = $current->parentNode) {
            if ($current->isSameNode($root)) {
                return true;
            }
        }

        return false;
    }
}
