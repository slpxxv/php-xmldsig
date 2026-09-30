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

namespace XmlDSig\Internal;

use XmlDSig\Algorithm\KeyType;
use XmlDSig\Exception\InvalidKey;

/**
 * @internal
 */
final class OpenSsl
{
    /**
     * Drains the OpenSSL error queue and returns its messages.
     */
    public static function lastError(): string
    {
        $errors = [];
        while (($error = \openssl_error_string()) !== false) {
            $errors[] = $error;
        }

        return $errors === [] ? 'unknown OpenSSL error' : \implode('; ', $errors);
    }

    public static function keyType(\OpenSSLAsymmetricKey $key): KeyType
    {
        return match (self::details($key)['type'] ?? null) {
            \OPENSSL_KEYTYPE_RSA => KeyType::Rsa,
            \OPENSSL_KEYTYPE_EC => KeyType::Ec,
            default => throw InvalidKey::unsupportedType(),
        };
    }

    public static function keyBits(\OpenSSLAsymmetricKey $key): int
    {
        return (int) (self::details($key)['bits'] ?? 0);
    }

    /**
     * @throws InvalidKey
     */
    public static function readFile(string $path): string
    {
        $contents = \is_file($path) && \is_readable($path) ? \file_get_contents($path) : false;
        if ($contents === false) {
            throw InvalidKey::fileNotReadable($path);
        }

        return $contents;
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function details(\OpenSSLAsymmetricKey $key): array
    {
        $details = \openssl_pkey_get_details($key);
        if ($details === false) {
            throw InvalidKey::unreadable('key details', self::lastError());
        }

        return $details;
    }
}
