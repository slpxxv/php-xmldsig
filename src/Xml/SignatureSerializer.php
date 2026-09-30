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

namespace XmlDSig\Xml;

use XmlDSig\Model\KeyInfo;
use XmlDSig\Model\Reference;
use XmlDSig\Model\Signature;
use XmlDSig\Model\SignedInfo;
use XmlDSig\Model\TransformSpec;

/**
 * Maps the signature model to a detached ds:Signature DOM element.
 */
final class SignatureSerializer
{
    public function serialize(Signature $signature, \DOMDocument $document): SignatureElement
    {
        $root = $this->element($document, 'Signature');
        if ($signature->id !== null) {
            $root->setAttribute('Id', $signature->id);
        }

        $root->appendChild($this->signedInfo($document, $signature->signedInfo));
        $root->appendChild($this->element($document, 'SignatureValue', \base64_encode($signature->signatureValue)));
        if ($signature->keyInfo !== null) {
            $root->appendChild($this->keyInfo($document, $signature->keyInfo));
        }

        return new SignatureElement($root);
    }

    private function signedInfo(\DOMDocument $document, SignedInfo $signedInfo): \DOMElement
    {
        $element = $this->element($document, 'SignedInfo');
        $canonicalization = $signedInfo->canonicalization->value;
        $element->appendChild($this->algorithm($document, 'CanonicalizationMethod', $canonicalization));
        $element->appendChild($this->algorithm($document, 'SignatureMethod', $signedInfo->signatureAlgorithm->value));
        foreach ($signedInfo->references as $reference) {
            $element->appendChild($this->reference($document, $reference));
        }

        return $element;
    }

    private function reference(\DOMDocument $document, Reference $reference): \DOMElement
    {
        $element = $this->element($document, 'Reference');
        if ($reference->id !== null) {
            $element->setAttribute('Id', $reference->id);
        }
        $element->setAttribute('URI', $reference->uri);
        if ($reference->type !== null) {
            $element->setAttribute('Type', $reference->type);
        }

        if ($reference->transforms !== []) {
            $transforms = $element->appendChild($this->element($document, 'Transforms'));
            foreach ($reference->transforms as $transform) {
                $transforms->appendChild($this->transform($document, $transform));
            }
        }

        $element->appendChild($this->algorithm($document, 'DigestMethod', $reference->digestAlgorithm->value));
        $element->appendChild($this->element($document, 'DigestValue', \base64_encode($reference->digestValue)));

        return $element;
    }

    private function transform(\DOMDocument $document, TransformSpec $transform): \DOMElement
    {
        $element = $this->algorithm($document, 'Transform', $transform->algorithm);
        if ($transform->inclusiveNamespaces !== []) {
            $inclusive = $document->createElementNS(
                XmlNamespace::Ec->value,
                XmlNamespace::Ec->qualify('InclusiveNamespaces'),
            );
            $inclusive->setAttribute('PrefixList', \implode(' ', $transform->inclusiveNamespaces));
            $element->appendChild($inclusive);
        }

        return $element;
    }

    private function keyInfo(\DOMDocument $document, KeyInfo $keyInfo): \DOMElement
    {
        $element = $this->element($document, 'KeyInfo');
        if ($keyInfo->keyName !== null) {
            $element->appendChild($this->element($document, 'KeyName', $keyInfo->keyName));
        }

        if ($keyInfo->x509Certificates !== []) {
            $data = $element->appendChild($this->element($document, 'X509Data'));
            foreach ($keyInfo->x509Certificates as $der) {
                $data->appendChild($this->element($document, 'X509Certificate', \base64_encode($der)));
            }
        }

        return $element;
    }

    private function algorithm(\DOMDocument $document, string $name, string $algorithm): \DOMElement
    {
        $element = $this->element($document, $name);
        $element->setAttribute('Algorithm', $algorithm);

        return $element;
    }

    private function element(\DOMDocument $document, string $name, ?string $text = null): \DOMElement
    {
        $element = $document->createElementNS(XmlNamespace::Ds->value, XmlNamespace::Ds->qualify($name));
        if ($text !== null) {
            $element->appendChild($document->createTextNode($text));
        }

        return $element;
    }
}
