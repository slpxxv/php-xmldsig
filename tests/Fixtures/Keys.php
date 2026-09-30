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

namespace XmlDSigTests\Fixtures;

/**
 * Generates key material once per test run, so no secrets are committed.
 */
final class Keys
{
    /** @var array<string, string> */
    private static array $cache = [];

    public static function rsaPrivatePem(?string $passphrase = null): string
    {
        return self::export(
            'rsa',
            ['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048],
            $passphrase,
        );
    }

    public static function ecPrivatePem(string $curve = 'prime256v1'): string
    {
        return self::export('ec-' . $curve, ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
    }

    public static function certificatePem(string $privatePem, string $commonName = 'xmldsig-test'): string
    {
        $cacheKey = 'cert-' . \md5($privatePem . $commonName);

        return self::$cache[$cacheKey] ??= (static function () use ($privatePem, $commonName): string {
            $key = \openssl_pkey_get_private($privatePem);
            \assert($key !== false);
            $csr = \openssl_csr_new(['commonName' => $commonName], $key, ['digest_alg' => 'sha256']);
            \assert($csr instanceof \OpenSSLCertificateSigningRequest);
            $certificate = \openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
            \assert($certificate !== false);
            \openssl_x509_export($certificate, $pem);

            return $pem;
        })();
    }

    /**
     * @param array<string, int|string> $options
     */
    private static function export(string $name, array $options, ?string $passphrase = null): string
    {
        $pem = self::$cache[$name] ??= (static function () use ($options): string {
            $key = \openssl_pkey_new($options);
            \assert($key !== false);
            \openssl_pkey_export($key, $pem);

            return $pem;
        })();

        if ($passphrase === null) {
            return $pem;
        }

        $key = \openssl_pkey_get_private($pem);
        \assert($key !== false);
        \openssl_pkey_export($key, $encrypted, $passphrase);

        return $encrypted;
    }
}
