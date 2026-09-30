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

namespace XmlDSig\Signing;

use XmlDSig\Algorithm\AlgorithmPolicy;
use XmlDSig\Canonicalization\Canonicalizer;
use XmlDSig\Crypto\Signature\SignatureMethodRegistry;
use XmlDSig\Exception\XmlDSigException;
use XmlDSig\Model\Signature;
use XmlDSig\Xml\SignatureSerializer;

final readonly class XmlSigner
{
    public function __construct(
        private SignedInfoFactory $signedInfoFactory,
        private SignatureSerializer $serializer,
        private Canonicalizer $canonicalizer,
        private SignatureMethodRegistry $signatureMethods,
        private AlgorithmPolicy $policy,
    ) {
    }

    /**
     * Signs the document in place and returns the inserted ds:Signature element.
     *
     * The document is left untouched when signing fails.
     *
     * @throws XmlDSigException
     */
    public function sign(\DOMDocument $document, SigningRequest $request): \DOMElement
    {
        $this->assertAllowed($request);

        $signedInfo = $this->signedInfoFactory->create($document, $request);
        $signature = $this->serializer->serialize(
            new Signature($signedInfo, keyInfo: $request->keyInfo?->keyInfo(), id: $request->signatureId),
            $document,
        );

        $request->placement->place($signature->element);
        try {
            // Canonicalized in place, so inclusive C14N sees the ancestors' namespaces like a verifier does.
            $octets = $this->canonicalizer->canonicalize(
                $signature->signedInfo(),
                $signedInfo->canonicalization,
                $signedInfo->inclusiveNamespaces,
            );
            $signature->setSignatureValue(
                $this->signatureMethods
                    ->for($request->signingKey->algorithm)
                    ->sign($octets, $request->signingKey->key, $request->signingKey->algorithm),
            );
        } catch (\Throwable $e) {
            $signature->element->parentNode?->removeChild($signature->element);

            throw $e;
        }

        return $signature->element;
    }

    private function assertAllowed(SigningRequest $request): void
    {
        $this->policy->assertSignatureAllowed($request->signingKey->algorithm);
        foreach ($request->references as $reference) {
            $this->policy->assertDigestAllowed($reference->digestAlgorithm);
        }
    }
}
