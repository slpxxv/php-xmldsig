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

namespace XmlDSigTests\Verification;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\AlgorithmPolicy;
use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Algorithm\DigestAlgorithm;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\AlgorithmNotAllowed;
use XmlDSig\Exception\DuplicateId;
use XmlDSig\Exception\VerificationFailed;
use XmlDSig\Key\PrivateKey;
use XmlDSig\Key\X509Certificate;
use XmlDSig\KeyInfo\X509DataSource;
use XmlDSig\Signing\Placement\AppendToElement;
use XmlDSig\Signing\ReferenceDefinition;
use XmlDSig\Signing\SigningKey;
use XmlDSig\Signing\SigningRequest;
use XmlDSig\Verification\KeyResolver\PinnedCertificateResolver;
use XmlDSig\Verification\KeyResolver\StaticKeyResolver;
use XmlDSig\Verification\SignatureLocator;
use XmlDSig\Verification\VerifiedSignature;
use XmlDSig\Verification\XmlVerifier;
use XmlDSig\XmlDSig;
use XmlDSigTests\Fixtures\Keys;

#[CoversClass(XmlVerifier::class)]
#[CoversClass(VerifiedSignature::class)]
#[CoversClass(SignatureLocator::class)]
#[CoversClass(StaticKeyResolver::class)]
#[CoversClass(PinnedCertificateResolver::class)]
#[CoversClass(VerificationFailed::class)]
#[CoversClass(XmlDSig::class)]
final class XmlVerifierTest extends TestCase
{
    private const XML = '<acme:batch xmlns:acme="urn:acme">'
        . '<acme:invoice ID="inv-1"><amount>100</amount></acme:invoice>'
        . '</acme:batch>';

    /**
     * @return iterable<string, array{SignatureAlgorithm, string, CanonicalizationAlgorithm}>
     */
    public static function algorithms(): iterable
    {
        yield 'RSA exclusive' => [SignatureAlgorithm::RsaSha256, 'rsa', CanonicalizationAlgorithm::Exclusive];
        yield 'RSA inclusive' => [SignatureAlgorithm::RsaSha512, 'rsa', CanonicalizationAlgorithm::Inclusive];
        yield 'ECDSA exclusive' => [SignatureAlgorithm::EcdsaSha256, 'ec', CanonicalizationAlgorithm::Exclusive];
        yield 'ECDSA inclusive' => [SignatureAlgorithm::EcdsaSha384, 'ec', CanonicalizationAlgorithm::Inclusive];
    }

    #[DataProvider('algorithms')]
    public function testVerifiesOwnSignatureAfterReparsing(
        SignatureAlgorithm $algorithm,
        string $keyType,
        CanonicalizationAlgorithm $canonicalization,
    ): void {
        $pem = $keyType === 'rsa' ? Keys::rsaPrivatePem() : Keys::ecPrivatePem();
        $document = $this->reload($this->sign($pem, $algorithm, $canonicalization));

        $verified = XmlDSig::verifier(new StaticKeyResolver(PrivateKey::fromPem($pem)->publicKey()))
            ->verify($document);

        self::assertTrue($verified->covers($this->element($document, 'amount')));
        self::assertFalse($verified->covers($this->root($document)));
    }

    public function testPinnedCertificateIsAccepted(): void
    {
        $pem = Keys::rsaPrivatePem();
        $certificate = X509Certificate::fromPem(Keys::certificatePem($pem));

        $verified = XmlDSig::verifier(new PinnedCertificateResolver($certificate))
            ->verify($this->sign($pem, certificate: $certificate));

        self::assertCount(1, $verified->signedNodes);
    }

    public function testUnpinnedCertificateIsRejected(): void
    {
        $pem = Keys::rsaPrivatePem();
        $attacker = Keys::ecPrivatePem();
        $attackerCertificate = X509Certificate::fromPem(Keys::certificatePem($attacker));
        $document = $this->sign($attacker, SignatureAlgorithm::EcdsaSha256, certificate: $attackerCertificate);

        $this->expectExceptionObject(VerificationFailed::untrustedKey());

        XmlDSig::verifier(new PinnedCertificateResolver(X509Certificate::fromPem(Keys::certificatePem($pem))))
            ->verify($document);
    }

    public function testModifiedContentIsRejected(): void
    {
        $pem = Keys::rsaPrivatePem();
        $document = $this->sign($pem);
        $this->element($document, 'amount')->textContent = '1000000';

        $this->expectExceptionObject(VerificationFailed::digestMismatch('#inv-1'));

        $this->verifier($pem)->verify($document);
    }

    public function testModifiedSignedInfoIsRejected(): void
    {
        $pem = Keys::rsaPrivatePem();
        $document = $this->sign($pem);
        $this->element($document, 'Reference')->setAttribute('Id', 'injected');

        $this->expectExceptionObject(VerificationFailed::invalidSignatureValue());

        $this->verifier($pem)->verify($document);
    }

    public function testWrongKeyIsRejected(): void
    {
        $document = $this->sign(Keys::rsaPrivatePem());

        $this->expectExceptionObject(VerificationFailed::keyAlgorithmMismatch());

        $this->verifier(Keys::ecPrivatePem())->verify($document);
    }

    public function testSignatureWrappingWithDuplicateIdIsRejected(): void
    {
        $pem = Keys::rsaPrivatePem();
        $document = $this->sign($pem);
        $original = $this->element($document, 'invoice');
        $evil = $original->cloneNode(true);
        \assert($evil instanceof \DOMElement);
        $evil->getElementsByTagName('amount')->item(0)?->replaceChildren('1000000');
        $copiedSignature = $evil->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')->item(0);
        \assert($copiedSignature !== null);
        $evil->removeChild($copiedSignature);
        $this->root($document)->insertBefore($evil, $original);

        $this->expectException(DuplicateId::class);

        $this->verifier($pem)->verify($document);
    }

    public function testSha1IsRejectedByDefault(): void
    {
        $pem = Keys::rsaPrivatePem();
        $document = new \DOMDocument();
        $document->loadXML(self::XML);
        XmlDSig::signer(AlgorithmPolicy::legacy())->sign($document, new SigningRequest(
            new SigningKey(PrivateKey::fromPem($pem), SignatureAlgorithm::RsaSha1),
            [ReferenceDefinition::enveloped('#inv-1', DigestAlgorithm::Sha1)],
            new AppendToElement($this->element($document, 'invoice')),
        ));

        $this->expectException(AlgorithmNotAllowed::class);

        $this->verifier($pem)->verify($document);
    }

    public function testMissingSignatureIsReported(): void
    {
        $document = new \DOMDocument();
        $document->loadXML(self::XML);

        $this->expectExceptionObject(VerificationFailed::signatureNotFound());

        $this->verifier(Keys::rsaPrivatePem())->verify($document);
    }

    public function testMultipleSignaturesRequireExplicitChoice(): void
    {
        $pem = Keys::rsaPrivatePem();
        $document = $this->sign($pem);
        $second = $this->element($document, 'Signature')->cloneNode(true);
        $this->root($document)->appendChild($second);

        $this->expectExceptionObject(VerificationFailed::ambiguousSignature(2));

        $this->verifier($pem)->verify($document);
    }

    public function testExplicitSignatureIsVerified(): void
    {
        $pem = Keys::rsaPrivatePem();
        $document = $this->sign($pem);
        $signature = $this->element($document, 'Signature');
        $this->root($document)->appendChild($document->createElement('unsigned'));

        $verified = $this->verifier($pem)->verify($document, $signature);

        self::assertFalse($verified->covers($this->element($document, 'unsigned')));
    }

    private function verifier(string $pem): XmlVerifier
    {
        return XmlDSig::verifier(new StaticKeyResolver(PrivateKey::fromPem($pem)->publicKey()));
    }

    private function sign(
        string $pem,
        SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256,
        CanonicalizationAlgorithm $canonicalization = CanonicalizationAlgorithm::Exclusive,
        ?X509Certificate $certificate = null,
    ): \DOMDocument {
        $document = new \DOMDocument();
        $document->loadXML(self::XML);

        XmlDSig::signer()->sign($document, new SigningRequest(
            new SigningKey(PrivateKey::fromPem($pem), $algorithm),
            [ReferenceDefinition::enveloped('#inv-1', canonicalization: $canonicalization)],
            new AppendToElement($this->element($document, 'invoice')),
            $canonicalization,
            $certificate === null ? null : new X509DataSource($certificate),
        ));

        return $document;
    }

    private function reload(\DOMDocument $document): \DOMDocument
    {
        $reloaded = new \DOMDocument();
        $reloaded->loadXML((string) $document->saveXML());

        return $reloaded;
    }

    private function element(\DOMDocument $document, string $localName): \DOMElement
    {
        $element = $document->getElementsByTagNameNS('*', $localName)->item(0)
            ?? $document->getElementsByTagName($localName)->item(0);
        \assert($element instanceof \DOMElement);

        return $element;
    }

    private function root(\DOMDocument $document): \DOMElement
    {
        $root = $document->documentElement;
        \assert($root !== null);

        return $root;
    }
}
