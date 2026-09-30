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

namespace XmlDSigTests\Signing;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\AlgorithmPolicy;
use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Algorithm\DigestAlgorithm;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Canonicalization\DomCanonicalizer;
use XmlDSig\Crypto\Signature\SignatureMethod;
use XmlDSig\Crypto\Signature\SignatureMethodRegistry;
use XmlDSig\Exception\AlgorithmNotAllowed;
use XmlDSig\Exception\InvalidSigningRequest;
use XmlDSig\Exception\KeyAlgorithmMismatch;
use XmlDSig\Exception\SigningFailed;
use XmlDSig\Key\PrivateKey;
use XmlDSig\Key\X509Certificate;
use XmlDSig\KeyInfo\X509DataSource;
use XmlDSig\Reference\IdAttributes;
use XmlDSig\Reference\ReferenceDigester;
use XmlDSig\Reference\SameDocumentResolver;
use XmlDSig\Crypto\Digest\HashDigester;
use XmlDSig\Signing\Placement\AppendToElement;
use XmlDSig\Signing\Placement\InsertAfter;
use XmlDSig\Signing\ReferenceDefinition;
use XmlDSig\Signing\SignedInfoFactory;
use XmlDSig\Signing\SigningKey;
use XmlDSig\Signing\SigningRequest;
use XmlDSig\Signing\XmlSigner;
use XmlDSig\Transform\TransformPipeline;
use XmlDSig\Transform\TransformRegistry;
use XmlDSig\Xml\SignatureSerializer;
use XmlDSig\XmlDSig;
use XmlDSigTests\Fixtures\FailingSignatureMethod;
use XmlDSigTests\Fixtures\Keys;

#[CoversClass(XmlSigner::class)]
#[CoversClass(SignedInfoFactory::class)]
#[CoversClass(SigningRequest::class)]
#[CoversClass(SigningKey::class)]
#[CoversClass(ReferenceDefinition::class)]
#[CoversClass(AppendToElement::class)]
#[CoversClass(InsertAfter::class)]
#[CoversClass(X509DataSource::class)]
#[CoversClass(XmlDSig::class)]
final class XmlSignerTest extends TestCase
{
    public function testSignatureValueCoversSignedInfoCanonicalizedInContext(): void
    {
        $document = $this->document();
        $key = PrivateKey::fromPem(Keys::rsaPrivatePem());

        $signature = XmlDSig::signer()->sign($document, new SigningRequest(
            new SigningKey($key, SignatureAlgorithm::RsaSha256),
            [ReferenceDefinition::enveloped('#inv-1')],
            new AppendToElement($this->invoice($document)),
            CanonicalizationAlgorithm::Inclusive,
        ));

        $signedInfo = $signature->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'SignedInfo')->item(0);
        \assert($signedInfo instanceof \DOMElement);
        $octets = $signedInfo->C14N(false, false);
        self::assertStringContainsString('xmlns:acme="urn:acme"', $octets);

        $value = \base64_decode($this->text($signature, 'SignatureValue'), true);
        self::assertSame(1, \openssl_verify($octets, (string) $value, $key->publicKey()->handle(), 'sha256'));
    }

    public function testDigestIsComputedWithoutTheSignature(): void
    {
        $document = $this->document();
        $expected = \base64_encode(\hash('sha256', (string) $this->invoice($document)->C14N(true, false), true));

        $signature = XmlDSig::signer()->sign($document, $this->request($document));

        self::assertSame($expected, $this->text($signature, 'DigestValue'));
    }

    public function testEmbedsCertificateAndHonoursPlacement(): void
    {
        $document = $this->document();
        $pem = Keys::rsaPrivatePem();
        $certificate = X509Certificate::fromPem(Keys::certificatePem($pem));
        $number = $document->getElementsByTagName('number')->item(0);
        \assert($number instanceof \DOMElement);

        $signature = XmlDSig::signer()->sign($document, new SigningRequest(
            new SigningKey(PrivateKey::fromPem($pem), SignatureAlgorithm::RsaSha256),
            [ReferenceDefinition::enveloped('#inv-1')],
            new InsertAfter($number),
            keyInfo: new X509DataSource($certificate),
        ));

        self::assertTrue($number->nextSibling?->isSameNode($signature));
        self::assertSame(\base64_encode($certificate->toDer()), $this->text($signature, 'X509Certificate'));
    }

    public function testRejectsDisallowedDigest(): void
    {
        $document = $this->document();

        $this->expectException(AlgorithmNotAllowed::class);

        XmlDSig::signer()->sign($document, new SigningRequest(
            new SigningKey(PrivateKey::fromPem(Keys::rsaPrivatePem()), SignatureAlgorithm::RsaSha256),
            [ReferenceDefinition::enveloped('#inv-1', DigestAlgorithm::Sha1)],
            new AppendToElement($this->invoice($document)),
        ));
    }

    public function testLegacyPolicyAllowsSha1(): void
    {
        $document = $this->document();

        $signature = XmlDSig::signer(AlgorithmPolicy::legacy())->sign($document, new SigningRequest(
            new SigningKey(PrivateKey::fromPem(Keys::rsaPrivatePem()), SignatureAlgorithm::RsaSha1),
            [ReferenceDefinition::enveloped('#inv-1', DigestAlgorithm::Sha1)],
            new AppendToElement($this->invoice($document)),
        ));

        self::assertNotSame('', $this->text($signature, 'SignatureValue'));
    }

    public function testKeyMustMatchAlgorithm(): void
    {
        $this->expectException(KeyAlgorithmMismatch::class);

        new SigningKey(PrivateKey::fromPem(Keys::ecPrivatePem()), SignatureAlgorithm::RsaSha256);
    }

    public function testRequiresReferences(): void
    {
        $this->expectException(InvalidSigningRequest::class);

        new SigningRequest(
            new SigningKey(PrivateKey::fromPem(Keys::rsaPrivatePem()), SignatureAlgorithm::RsaSha256),
            [],
            new AppendToElement($this->invoice($this->document())),
        );
    }

    public function testDocumentIsUntouchedWhenSigningFails(): void
    {
        $document = $this->document();
        $before = $document->saveXML();

        try {
            $this->signerWith(new FailingSignatureMethod())->sign($document, $this->request($document));
            self::fail('Expected SigningFailed.');
        } catch (SigningFailed) {
        }

        self::assertSame($before, $document->saveXML());
    }

    private function signerWith(SignatureMethod $method): XmlSigner
    {
        $canonicalizer = new DomCanonicalizer();

        return new XmlSigner(
            new SignedInfoFactory(new ReferenceDigester(
                new SameDocumentResolver(IdAttributes::default()),
                new TransformPipeline(TransformRegistry::default($canonicalizer), $canonicalizer),
                new HashDigester(),
            )),
            new SignatureSerializer(),
            $canonicalizer,
            new SignatureMethodRegistry($method),
            AlgorithmPolicy::secure(),
        );
    }

    private function request(\DOMDocument $document): SigningRequest
    {
        return new SigningRequest(
            new SigningKey(PrivateKey::fromPem(Keys::rsaPrivatePem()), SignatureAlgorithm::RsaSha256),
            [ReferenceDefinition::enveloped('#inv-1')],
            new AppendToElement($this->invoice($document)),
        );
    }

    private function document(): \DOMDocument
    {
        $document = new \DOMDocument();
        $document->loadXML(
            '<acme:batch xmlns:acme="urn:acme"><acme:invoice ID="inv-1"><number>1</number></acme:invoice></acme:batch>',
        );

        return $document;
    }

    private function invoice(\DOMDocument $document): \DOMElement
    {
        $invoice = $document->getElementsByTagNameNS('urn:acme', 'invoice')->item(0);
        \assert($invoice instanceof \DOMElement);

        return $invoice;
    }

    private function text(\DOMElement $signature, string $name): string
    {
        return (string) $signature->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', $name)
            ->item(0)?->textContent;
    }
}
