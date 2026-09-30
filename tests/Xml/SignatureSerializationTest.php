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

namespace XmlDSigTests\Xml;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Algorithm\DigestAlgorithm;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\MalformedSignature;
use XmlDSig\Model\KeyInfo;
use XmlDSig\Model\Reference;
use XmlDSig\Model\Signature;
use XmlDSig\Model\SignedInfo;
use XmlDSig\Model\TransformSpec;
use XmlDSig\Xml\SignatureElement;
use XmlDSig\Xml\SignatureParser;
use XmlDSig\Xml\SignatureSerializer;
use XmlDSig\Xml\XmlNamespace;

#[CoversClass(SignatureSerializer::class)]
#[CoversClass(SignatureParser::class)]
#[CoversClass(SignatureElement::class)]
#[CoversClass(XmlNamespace::class)]
#[CoversClass(MalformedSignature::class)]
final class SignatureSerializationTest extends TestCase
{
    public function testRoundTrip(): void
    {
        $signature = new Signature(
            new SignedInfo(
                CanonicalizationAlgorithm::Exclusive,
                SignatureAlgorithm::RsaSha256,
                [
                    new Reference(
                        '#a',
                        DigestAlgorithm::Sha256,
                        \random_bytes(32),
                        [
                            TransformSpec::envelopedSignature(),
                            TransformSpec::canonicalization(CanonicalizationAlgorithm::Exclusive, ['ns1', 'ns2']),
                        ],
                        'ref-1',
                        'urn:type',
                    ),
                ],
            ),
            \random_bytes(256),
            new KeyInfo('key-1', [\random_bytes(100)]),
            'sig-1',
        );

        $document = new \DOMDocument();
        $element = (new SignatureSerializer())->serialize($signature, $document);
        $document->appendChild($element->element);
        $reloaded = new \DOMDocument();
        $reloaded->loadXML((string) $document->saveXML());

        self::assertEquals(
            $signature,
            (new SignatureParser())->parse(new SignatureElement($this->root($reloaded))),
        );
    }

    public function testRejectsSignatureWithoutSignedInfoFirst(): void
    {
        $this->expectException(MalformedSignature::class);

        $this->parse('<ds:SignatureValue>AA==</ds:SignatureValue><ds:SignedInfo/>');
    }

    public function testRejectsDuplicatedSignatureValue(): void
    {
        $this->expectException(MalformedSignature::class);

        $this->parse(
            '<ds:SignedInfo>'
            . '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            . '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            . '<ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            . '<ds:DigestValue>AA==</ds:DigestValue></ds:Reference>'
            . '</ds:SignedInfo>'
            . '<ds:SignatureValue>AA==</ds:SignatureValue><ds:SignatureValue>AA==</ds:SignatureValue>',
        );
    }

    public function testRejectsInvalidBase64(): void
    {
        $this->expectException(MalformedSignature::class);

        $this->parse(
            '<ds:SignedInfo>'
            . '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            . '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            . '<ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            . '<ds:DigestValue>AA==</ds:DigestValue></ds:Reference>'
            . '</ds:SignedInfo>'
            . '<ds:SignatureValue>not base64!</ds:SignatureValue>',
        );
    }

    private function parse(string $children): Signature
    {
        $document = new \DOMDocument();
        $document->loadXML(
            \sprintf('<ds:Signature xmlns:ds="%s">%s</ds:Signature>', XmlNamespace::Ds->value, $children),
        );

        return (new SignatureParser())->parse(new SignatureElement($this->root($document)));
    }

    private function root(\DOMDocument $document): \DOMElement
    {
        $root = $document->documentElement;
        \assert($root !== null);

        return $root;
    }
}
