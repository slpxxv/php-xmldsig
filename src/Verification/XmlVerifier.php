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

namespace XmlDSig\Verification;

use XmlDSig\Algorithm\AlgorithmPolicy;
use XmlDSig\Canonicalization\Canonicalizer;
use XmlDSig\Crypto\Signature\SignatureMethodRegistry;
use XmlDSig\Exception\VerificationFailed;
use XmlDSig\Exception\XmlDSigException;
use XmlDSig\Model\Signature;
use XmlDSig\Reference\ReferenceDigester;
use XmlDSig\Verification\KeyResolver\KeyResolver;
use XmlDSig\Xml\SignatureElement;
use XmlDSig\Xml\SignatureParser;

final readonly class XmlVerifier
{
    public function __construct(
        private SignatureLocator $locator,
        private SignatureParser $parser,
        private KeyResolver $keyResolver,
        private Canonicalizer $canonicalizer,
        private SignatureMethodRegistry $signatureMethods,
        private ReferenceDigester $digester,
        private AlgorithmPolicy $policy,
    ) {
    }

    /**
     * Verifies the signature or throws; there is no "false" result to forget to check.
     *
     * @param \DOMElement|null $signature The ds:Signature to verify, required when the document holds several.
     *
     * @throws XmlDSigException
     */
    public function verify(\DOMDocument $document, ?\DOMElement $signature = null): VerifiedSignature
    {
        $signature ??= $this->locator->locate($document);
        if ($signature->ownerDocument !== $document) {
            throw VerificationFailed::foreignSignature();
        }

        $element = new SignatureElement($signature);
        $model = $this->parser->parse($element);
        $this->assertAllowed($model);

        // Authenticate SignedInfo first, so no transform runs on attacker-chosen input.
        $algorithm = $model->signedInfo->signatureAlgorithm;
        $key = $this->keyResolver->resolve($model->keyInfo, $algorithm);
        if ($key->type !== $algorithm->keyType()) {
            throw VerificationFailed::keyAlgorithmMismatch();
        }

        $octets = $this->canonicalizer->canonicalize($element->signedInfo(), $model->signedInfo->canonicalization);
        if (!$this->signatureMethods->for($algorithm)->verify($octets, $model->signatureValue, $key, $algorithm)) {
            throw VerificationFailed::invalidSignatureValue();
        }

        $signedNodes = [];
        foreach ($model->signedInfo->references as $reference) {
            $result = $this->digester->digest(
                $document,
                $reference->uri,
                $reference->transforms,
                $reference->digestAlgorithm,
                $signature,
            );
            if (!\hash_equals($reference->digestValue, $result->digest)) {
                throw VerificationFailed::digestMismatch($reference->uri);
            }
            $signedNodes[] = $result->node;
        }

        return new VerifiedSignature($model, $signedNodes, $key);
    }

    private function assertAllowed(Signature $signature): void
    {
        $this->policy->assertSignatureAllowed($signature->signedInfo->signatureAlgorithm);
        foreach ($signature->signedInfo->references as $reference) {
            $this->policy->assertDigestAllowed($reference->digestAlgorithm);
        }
    }
}
