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

use XmlDSig\Exception\VerificationFailed;
use XmlDSig\Xml\XmlNamespace;

final class SignatureLocator
{
    /**
     * Finds the only ds:Signature; ambiguity is an error rather than a guess.
     *
     * @throws VerificationFailed
     */
    public function locate(\DOMDocument $document): \DOMElement
    {
        $signatures = $document->getElementsByTagNameNS(XmlNamespace::Ds->value, 'Signature');

        return match ($signatures->length) {
            0 => throw VerificationFailed::signatureNotFound(),
            1 => $signatures->item(0) ?? throw VerificationFailed::signatureNotFound(),
            default => throw VerificationFailed::ambiguousSignature($signatures->length),
        };
    }
}
