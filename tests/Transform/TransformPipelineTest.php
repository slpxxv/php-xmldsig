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

namespace XmlDSigTests\Transform;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Canonicalization\DomCanonicalizer;
use XmlDSig\Exception\UnsupportedAlgorithm;
use XmlDSig\Model\TransformSpec;
use XmlDSig\Transform\CanonicalizationTransform;
use XmlDSig\Transform\EnvelopedSignatureTransform;
use XmlDSig\Transform\TransformData;
use XmlDSig\Transform\TransformPipeline;
use XmlDSig\Transform\TransformRegistry;

#[CoversClass(TransformPipeline::class)]
#[CoversClass(TransformRegistry::class)]
#[CoversClass(TransformData::class)]
#[CoversClass(EnvelopedSignatureTransform::class)]
#[CoversClass(CanonicalizationTransform::class)]
#[CoversClass(DomCanonicalizer::class)]
#[CoversClass(TransformSpec::class)]
final class TransformPipelineTest extends TestCase
{
    private const XML = <<<'XML'
        <root xmlns:a="urn:a" xmlns:b="urn:b">
          <a:item ID="x"><!-- note --><b:v>1</b:v><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></a:item>
        </root>
        XML;

    public function testEnvelopedTransformExcludesOnlyTheSignatureAndRestoresIt(): void
    {
        [$document, $item, $signature] = $this->load();

        $octets = $this->pipeline()->process(
            TransformData::nodeSet($item),
            [
                TransformSpec::envelopedSignature(),
                TransformSpec::canonicalization(CanonicalizationAlgorithm::Exclusive),
            ],
            $signature,
        );

        self::assertSame('<a:item xmlns:a="urn:a" ID="x"><b:v xmlns:b="urn:b">1</b:v></a:item>', $octets);
        self::assertTrue($signature->parentNode?->isSameNode($item));
        self::assertStringContainsString('ds:Signature', (string) $document->saveXML());
    }

    public function testInclusiveCanonicalizationKeepsAncestorNamespaces(): void
    {
        [, $item] = $this->load();

        $octets = $this->pipeline()->process(
            TransformData::nodeSet($item),
            [TransformSpec::envelopedSignature()],
            null,
        );

        self::assertStringStartsWith('<a:item xmlns:a="urn:a" xmlns:b="urn:b" ID="x">', $octets);
    }

    public function testCommentsAreStrippedFromSameDocumentReferences(): void
    {
        [, $item] = $this->load();

        $octets = $this->pipeline()->process(
            TransformData::nodeSet($item),
            [TransformSpec::canonicalization(CanonicalizationAlgorithm::ExclusiveWithComments)],
            null,
        );

        self::assertStringNotContainsString('note', $octets);
    }

    public function testInclusiveNamespacePrefixesAreHonoured(): void
    {
        [, $item] = $this->load();

        $octets = $this->pipeline()->process(
            TransformData::nodeSet($item),
            [TransformSpec::canonicalization(CanonicalizationAlgorithm::Exclusive, ['b'])],
            null,
        );

        self::assertStringStartsWith('<a:item xmlns:a="urn:a" xmlns:b="urn:b" ID="x">', $octets);
    }

    public function testUnknownTransformIsRejected(): void
    {
        [, $item] = $this->load();

        $this->expectException(UnsupportedAlgorithm::class);

        $this->pipeline()->process(TransformData::nodeSet($item), [new TransformSpec('urn:xslt')], null);
    }

    private function pipeline(): TransformPipeline
    {
        $canonicalizer = new DomCanonicalizer();

        return new TransformPipeline(TransformRegistry::default($canonicalizer), $canonicalizer);
    }

    /**
     * @return array{\DOMDocument, \DOMElement, \DOMElement}
     */
    private function load(): array
    {
        $document = new \DOMDocument();
        $document->loadXML(self::XML);
        $item = $document->getElementsByTagNameNS('urn:a', 'item')->item(0);
        $signature = $document->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')->item(0);
        \assert($item instanceof \DOMElement && $signature instanceof \DOMElement);

        return [$document, $item, $signature];
    }
}
