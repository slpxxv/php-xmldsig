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

namespace XmlDSig\Xml;

use XmlDSig\Exception\MalformedSignature;

/**
 * DOM view of a ds:Signature element that enforces the XMLDSig child structure.
 */
final readonly class SignatureElement
{
    /**
     * @throws MalformedSignature
     */
    public function __construct(
        public \DOMElement $element,
    ) {
        if (!self::is($element, 'Signature')) {
            throw MalformedSignature::because('expected ds:Signature element.');
        }
    }

    /**
     * @throws MalformedSignature
     */
    public function signedInfo(): \DOMElement
    {
        $first = self::elementChildren($this->element)[0] ?? null;
        if ($first === null || !self::is($first, 'SignedInfo')) {
            throw MalformedSignature::because('ds:SignedInfo must be the first child.');
        }

        return $first;
    }

    /**
     * @throws MalformedSignature
     */
    public function signatureValue(): \DOMElement
    {
        return self::requireChild($this->element, 'SignatureValue');
    }

    public function setSignatureValue(string $value): void
    {
        $this->signatureValue()->textContent = \base64_encode($value);
    }

    public static function is(\DOMNode $node, string $localName, XmlNamespace $ns = XmlNamespace::Ds): bool
    {
        return $node instanceof \DOMElement && $node->namespaceURI === $ns->value && $node->localName === $localName;
    }

    /**
     * @return list<\DOMElement>
     */
    public static function elementChildren(\DOMElement $parent): array
    {
        $children = [];
        foreach ($parent->childNodes as $child) {
            if ($child instanceof \DOMElement) {
                $children[] = $child;
            }
        }

        return $children;
    }

    /**
     * @return list<\DOMElement>
     */
    public static function children(
        \DOMElement $parent,
        string $localName,
        XmlNamespace $ns = XmlNamespace::Ds,
    ): array {
        return \array_values(\array_filter(
            self::elementChildren($parent),
            static fn (\DOMElement $child): bool => self::is($child, $localName, $ns),
        ));
    }

    /**
     * @throws MalformedSignature
     */
    public static function requireChild(\DOMElement $parent, string $localName): \DOMElement
    {
        $children = self::children($parent, $localName);
        if (\count($children) !== 1) {
            throw MalformedSignature::because(
                \sprintf('expected exactly one ds:%s in ds:%s.', $localName, $parent->localName),
            );
        }

        return $children[0];
    }

    /**
     * @throws MalformedSignature
     */
    public static function optionalChild(\DOMElement $parent, string $localName): ?\DOMElement
    {
        $children = self::children($parent, $localName);
        if (\count($children) > 1) {
            throw MalformedSignature::because(
                \sprintf('expected at most one ds:%s in ds:%s.', $localName, $parent->localName),
            );
        }

        return $children[0] ?? null;
    }
}
