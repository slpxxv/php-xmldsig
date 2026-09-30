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

namespace XmlDSig\Algorithm;

use XmlDSig\Exception\UnsupportedAlgorithm;

enum DigestAlgorithm: string
{
    case Sha1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    case Sha224 = 'http://www.w3.org/2001/04/xmldsig-more#sha224';
    case Sha256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    case Sha384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    case Sha512 = 'http://www.w3.org/2001/04/xmlenc#sha512';

    public static function fromUri(string $uri): self
    {
        return self::tryFrom($uri) ?? throw UnsupportedAlgorithm::forUri($uri);
    }

    /**
     * Name understood by ext-hash and ext-openssl.
     */
    public function hashName(): string
    {
        return match ($this) {
            self::Sha1 => 'sha1',
            self::Sha224 => 'sha224',
            self::Sha256 => 'sha256',
            self::Sha384 => 'sha384',
            self::Sha512 => 'sha512',
        };
    }
}
