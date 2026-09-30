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

use XmlDSig\Exception\DuplicateId;
use XmlDSig\Exception\ReferenceNotFound;

/**
 * Resolves "", "#xpointer(/)", "#id" and "#xpointer(id('id'))".
 */
final readonly class SameDocumentResolver implements ReferenceResolver
{
    public function __construct(
        private IdAttributes $idAttributes,
    ) {
    }

    #[\Override]
    public function resolve(string $uri, \DOMDocument $document): \DOMNode
    {
        if ($uri === '' || $uri === '#xpointer(/)') {
            return $document;
        }

        if (!\str_starts_with($uri, '#')) {
            throw ReferenceNotFound::unsupportedUri($uri);
        }

        $fragment = \substr($uri, 1);
        if (\preg_match('/^xpointer\(id\([\'"](.+)[\'"]\)\)$/', $fragment, $match) === 1) {
            $fragment = $match[1];
        }

        return $this->findById($fragment, $document);
    }

    private function findById(string $id, \DOMDocument $document): \DOMElement
    {
        $found = null;
        foreach ($document->getElementsByTagName('*') as $element) {
            if ($this->idAttributes->idOf($element) !== $id) {
                continue;
            }
            if ($found !== null) {
                throw DuplicateId::forId($id);
            }
            $found = $element;
        }

        return $found ?? throw ReferenceNotFound::forId($id);
    }
}
