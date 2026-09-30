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

namespace XmlDSigTests\Reference;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use XmlDSig\Exception\DuplicateId;
use XmlDSig\Exception\ReferenceNotFound;
use XmlDSig\Reference\IdAttributes;
use XmlDSig\Reference\SameDocumentResolver;

#[CoversClass(SameDocumentResolver::class)]
#[CoversClass(IdAttributes::class)]
#[CoversClass(ReferenceNotFound::class)]
#[CoversClass(DuplicateId::class)]
final class SameDocumentResolverTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function uris(): iterable
    {
        yield 'ID' => ['#a', 'first'];
        yield 'Id' => ['#b', 'second'];
        yield 'xml:id' => ['#c', 'third'];
        yield 'xpointer id' => ["#xpointer(id('b'))", 'second'];
    }

    #[DataProvider('uris')]
    public function testResolvesById(string $uri, string $expectedName): void
    {
        $node = $this->resolver()->resolve($uri, $this->document());

        self::assertInstanceOf(\DOMElement::class, $node);
        self::assertSame($expectedName, $node->localName);
    }

    public function testEmptyUriIsWholeDocument(): void
    {
        $document = $this->document();

        self::assertSame($document, $this->resolver()->resolve('', $document));
    }

    public function testDuplicateIdIsRejected(): void
    {
        $document = new \DOMDocument();
        $document->loadXML('<r><x ID="a"/><wrapper><x ID="a"/></wrapper></r>');

        $this->expectException(DuplicateId::class);

        $this->resolver()->resolve('#a', $document);
    }

    public function testMissingIdIsRejected(): void
    {
        $this->expectException(ReferenceNotFound::class);

        $this->resolver()->resolve('#missing', $this->document());
    }

    public function testExternalUriIsRejected(): void
    {
        $this->expectException(ReferenceNotFound::class);

        $this->resolver()->resolve('https://example.com/doc.xml', $this->document());
    }

    private function resolver(): SameDocumentResolver
    {
        return new SameDocumentResolver(IdAttributes::default());
    }

    private function document(): \DOMDocument
    {
        $document = new \DOMDocument();
        $document->loadXML('<root><first ID="a"/><second Id="b"/><third xml:id="c"/></root>');

        return $document;
    }
}
