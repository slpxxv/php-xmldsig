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

namespace XmlDSig\Reference;

/**
 * Names of non-namespaced attributes treated as element IDs; xml:id is always honoured.
 */
final readonly class IdAttributes
{
    private const XML_NS = 'http://www.w3.org/XML/1998/namespace';

    /** @var list<string> */
    private array $names;

    public function __construct(string ...$names)
    {
        $this->names = \array_values($names);
    }

    public static function default(): self
    {
        return new self('ID', 'Id', 'id');
    }

    public function idOf(\DOMElement $element): ?string
    {
        foreach ($this->names as $name) {
            if ($element->hasAttribute($name)) {
                return $element->getAttribute($name);
            }
        }

        return $element->hasAttributeNS(self::XML_NS, 'id') ? $element->getAttributeNS(self::XML_NS, 'id') : null;
    }
}
