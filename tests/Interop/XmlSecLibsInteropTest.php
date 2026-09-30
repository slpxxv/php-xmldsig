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

namespace XmlDSigTests\Interop;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Key\PrivateKey;
use XmlDSig\Key\X509Certificate;
use XmlDSig\KeyInfo\X509DataSource;
use XmlDSig\Signing\Placement\AppendToElement;
use XmlDSig\Signing\ReferenceDefinition;
use XmlDSig\Signing\SigningKey;
use XmlDSig\Signing\SigningRequest;
use XmlDSig\Verification\KeyResolver\PinnedCertificateResolver;
use XmlDSig\XmlDSig;
use XmlDSigTests\Fixtures\Keys;

/**
 * Cross-checks against robrichards/xmlseclibs, the de facto PHP implementation.
 */
#[CoversNothing]
final class XmlSecLibsInteropTest extends TestCase
{
    private const XML = <<<'XML'
        <acme:batch xmlns:acme="urn:acme" xmlns:unused="urn:unused">
          <acme:invoice ID="inv-1">
            <acme:amount currency="PLN">100.00</acme:amount>
          </acme:invoice>
        </acme:batch>
        XML;

    /**
     * @return iterable<string, array{CanonicalizationAlgorithm}>
     */
    public static function canonicalizations(): iterable
    {
        yield 'exclusive' => [CanonicalizationAlgorithm::Exclusive];
        yield 'inclusive' => [CanonicalizationAlgorithm::Inclusive];
    }

    #[DataProvider('canonicalizations')]
    public function testXmlSecLibsVerifiesOurSignature(CanonicalizationAlgorithm $canonicalization): void
    {
        $pem = Keys::rsaPrivatePem();
        $document = $this->document();
        XmlDSig::signer()->sign($document, new SigningRequest(
            new SigningKey(PrivateKey::fromPem($pem), SignatureAlgorithm::RsaSha256),
            [ReferenceDefinition::enveloped('#inv-1', canonicalization: $canonicalization)],
            new AppendToElement($this->invoice($document)),
            $canonicalization,
        ));
        $document = $this->reload($document);

        $dsig = new XMLSecurityDSig();
        $dsig->idKeys = ['ID'];
        self::assertNotNull($dsig->locateSignature($document));
        $dsig->canonicalizeSignedInfo();
        self::assertTrue($dsig->validateReference());

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']);
        $key->loadKey($this->publicPem($pem));
        self::assertSame(1, $dsig->verify($key));
    }

    public function testWeVerifyXmlSecLibsSignature(): void
    {
        $pem = Keys::rsaPrivatePem();
        $certificatePem = Keys::certificatePem($pem);
        $document = $this->document();
        $invoice = $this->invoice($document);

        $dsig = new XMLSecurityDSig();
        $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $dsig->addReference(
            $invoice,
            XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID', 'overwrite' => false],
        );
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($pem);
        $dsig->sign($key, $invoice);
        $dsig->add509Cert($certificatePem);

        $trusted = X509Certificate::fromPem($certificatePem);
        $verified = XmlDSig::verifier(new PinnedCertificateResolver([$trusted]))->verify($this->reload($document));

        self::assertCount(1, $verified->signedNodes);
    }

    public function testCertificateWeEmbedIsReadableByXmlSecLibs(): void
    {
        $pem = Keys::rsaPrivatePem();
        $certificate = X509Certificate::fromPem(Keys::certificatePem($pem));
        $document = $this->document();
        XmlDSig::signer()->sign($document, new SigningRequest(
            new SigningKey(PrivateKey::fromPem($pem), SignatureAlgorithm::RsaSha256),
            [ReferenceDefinition::enveloped('#inv-1')],
            new AppendToElement($this->invoice($document)),
            keyInfo: new X509DataSource($certificate),
        ));

        $dsig = new XMLSecurityDSig();
        $dsig->idKeys = ['ID'];
        $dsig->locateSignature($document);
        $dsig->canonicalizeSignedInfo();
        $key = $dsig->locateKey();
        self::assertNotNull($key);
        \RobRichards\XMLSecLibs\XMLSecEnc::staticLocateKeyInfo($key, $dsig->sigNode);

        self::assertSame(1, $dsig->verify($key));
    }

    private function document(): \DOMDocument
    {
        $document = new \DOMDocument();
        $document->preserveWhiteSpace = true;
        $document->loadXML(self::XML);

        return $document;
    }

    private function reload(\DOMDocument $document): \DOMDocument
    {
        $reloaded = new \DOMDocument();
        $reloaded->loadXML((string) $document->saveXML());

        return $reloaded;
    }

    private function invoice(\DOMDocument $document): \DOMElement
    {
        $invoice = $document->getElementsByTagNameNS('urn:acme', 'invoice')->item(0);
        \assert($invoice instanceof \DOMElement);

        return $invoice;
    }

    private function publicPem(string $privatePem): string
    {
        $key = \openssl_pkey_get_private($privatePem);
        \assert($key !== false);
        $details = \openssl_pkey_get_details($key);
        \assert($details !== false && isset($details['key']) && \is_string($details['key']));

        return $details['key'];
    }
}
