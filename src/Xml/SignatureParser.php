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

namespace XmlDSig\Xml;

use XmlDSig\Algorithm\CanonicalizationAlgorithm;
use XmlDSig\Algorithm\DigestAlgorithm;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Exception\MalformedSignature;
use XmlDSig\Exception\UnsupportedAlgorithm;
use XmlDSig\Model\KeyInfo;
use XmlDSig\Model\Reference;
use XmlDSig\Model\Signature;
use XmlDSig\Model\SignedInfo;
use XmlDSig\Model\TransformSpec;

/**
 * Maps a ds:Signature DOM element to the signature model.
 */
final class SignatureParser
{
    /**
     * @throws MalformedSignature
     * @throws UnsupportedAlgorithm
     */
    public function parse(SignatureElement $signature): Signature
    {
        $keyInfo = SignatureElement::optionalChild($signature->element, 'KeyInfo');

        return new Signature(
            $this->signedInfo($signature->signedInfo()),
            $this->base64($signature->signatureValue()),
            $keyInfo === null ? null : $this->keyInfo($keyInfo),
            $this->optionalAttribute($signature->element, 'Id'),
        );
    }

    private function signedInfo(\DOMElement $element): SignedInfo
    {
        $references = \array_map(
            $this->reference(...),
            SignatureElement::children($element, 'Reference'),
        );
        if ($references === []) {
            throw MalformedSignature::because('ds:SignedInfo must contain at least one ds:Reference.');
        }

        return new SignedInfo(
            CanonicalizationAlgorithm::fromUri($this->algorithm($element, 'CanonicalizationMethod')),
            SignatureAlgorithm::fromUri($this->algorithm($element, 'SignatureMethod')),
            $references,
        );
    }

    private function reference(\DOMElement $element): Reference
    {
        if (!$element->hasAttribute('URI')) {
            throw MalformedSignature::because('ds:Reference without URI is not supported.');
        }

        $transforms = SignatureElement::optionalChild($element, 'Transforms');

        return new Reference(
            $element->getAttribute('URI'),
            DigestAlgorithm::fromUri($this->algorithm($element, 'DigestMethod')),
            $this->base64(SignatureElement::requireChild($element, 'DigestValue')),
            $transforms === null ? [] : \array_map(
                $this->transform(...),
                SignatureElement::children($transforms, 'Transform'),
            ),
            $this->optionalAttribute($element, 'Id'),
            $this->optionalAttribute($element, 'Type'),
        );
    }

    private function transform(\DOMElement $element): TransformSpec
    {
        $prefixes = [];
        $inclusive = SignatureElement::children($element, 'InclusiveNamespaces', XmlNamespace::Ec)[0] ?? null;
        if ($inclusive !== null) {
            $prefixes = \preg_split('/\s+/', \trim($inclusive->getAttribute('PrefixList')), -1, \PREG_SPLIT_NO_EMPTY);
        }

        return new TransformSpec($this->requireAttribute($element, 'Algorithm'), $prefixes === false ? [] : $prefixes);
    }

    private function keyInfo(\DOMElement $element): KeyInfo
    {
        $keyName = SignatureElement::optionalChild($element, 'KeyName');

        $certificates = [];
        foreach (SignatureElement::children($element, 'X509Data') as $data) {
            foreach (SignatureElement::children($data, 'X509Certificate') as $certificate) {
                $certificates[] = $this->base64($certificate);
            }
        }

        return new KeyInfo($keyName === null ? null : \trim($keyName->textContent), $certificates);
    }

    private function algorithm(\DOMElement $parent, string $name): string
    {
        return $this->requireAttribute(SignatureElement::requireChild($parent, $name), 'Algorithm');
    }

    private function requireAttribute(\DOMElement $element, string $name): string
    {
        if (!$element->hasAttribute($name)) {
            throw MalformedSignature::because(\sprintf('ds:%s requires the %s attribute.', $element->localName, $name));
        }

        return $element->getAttribute($name);
    }

    private function optionalAttribute(\DOMElement $element, string $name): ?string
    {
        return $element->hasAttribute($name) ? $element->getAttribute($name) : null;
    }

    private function base64(\DOMElement $element): string
    {
        $value = \base64_decode((string) \preg_replace('/\s+/', '', $element->textContent), true);
        if ($value === false || $value === '') {
            throw MalformedSignature::because(\sprintf('ds:%s is not valid base64.', $element->localName));
        }

        return $value;
    }
}
