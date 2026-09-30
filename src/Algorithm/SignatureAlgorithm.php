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

namespace XmlDSig\Algorithm;

use XmlDSig\Exception\UnsupportedAlgorithm;

enum SignatureAlgorithm: string
{
    case RsaSha1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    case RsaSha224 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224';
    case RsaSha256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    case RsaSha384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    case RsaSha512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    case EcdsaSha1 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1';
    case EcdsaSha224 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224';
    case EcdsaSha256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
    case EcdsaSha384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
    case EcdsaSha512 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';

    public static function fromUri(string $uri): self
    {
        return self::tryFrom($uri) ?? throw UnsupportedAlgorithm::forUri($uri);
    }

    /**
     * Digest the signature algorithm hashes SignedInfo with.
     */
    public function digest(): DigestAlgorithm
    {
        return match ($this) {
            self::RsaSha1, self::EcdsaSha1 => DigestAlgorithm::Sha1,
            self::RsaSha224, self::EcdsaSha224 => DigestAlgorithm::Sha224,
            self::RsaSha256, self::EcdsaSha256 => DigestAlgorithm::Sha256,
            self::RsaSha384, self::EcdsaSha384 => DigestAlgorithm::Sha384,
            self::RsaSha512, self::EcdsaSha512 => DigestAlgorithm::Sha512,
        };
    }

    public function keyType(): KeyType
    {
        return match ($this) {
            self::RsaSha1, self::RsaSha224, self::RsaSha256, self::RsaSha384, self::RsaSha512 => KeyType::Rsa,
            default => KeyType::Ec,
        };
    }
}
