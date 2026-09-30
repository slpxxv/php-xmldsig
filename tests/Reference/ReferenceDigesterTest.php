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

namespace XmlDSigTests\Reference;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Algorithm\DigestAlgorithm;
use XmlDSig\Canonicalization\DomCanonicalizer;
use XmlDSig\Crypto\Digest\HashDigester;
use XmlDSig\Model\TransformSpec;
use XmlDSig\Reference\IdAttributes;
use XmlDSig\Reference\ReferenceDigest;
use XmlDSig\Reference\ReferenceDigester;
use XmlDSig\Reference\SameDocumentResolver;
use XmlDSig\Transform\TransformPipeline;
use XmlDSig\Transform\TransformRegistry;

#[CoversClass(ReferenceDigester::class)]
#[CoversClass(ReferenceDigest::class)]
#[CoversClass(HashDigester::class)]
final class ReferenceDigesterTest extends TestCase
{
    public function testDigestsCanonicalFormOfReferencedElement(): void
    {
        $document = new \DOMDocument();
        $document->loadXML('<root><item ID="a" z="2"  y="1">text</item></root>');
        $canonicalizer = new DomCanonicalizer();
        $digester = new ReferenceDigester(
            new SameDocumentResolver(IdAttributes::default()),
            new TransformPipeline(TransformRegistry::default($canonicalizer), $canonicalizer),
            new HashDigester(),
        );

        $result = $digester->digest(
            $document,
            '#a',
            [TransformSpec::canonicalization(CanonicalizationAlgorithm::Exclusive)],
            DigestAlgorithm::Sha256,
        );

        self::assertSame('item', $result->node->nodeName);
        self::assertSame(\hash('sha256', '<item ID="a" y="1" z="2">text</item>', true), $result->digest);
    }
}
