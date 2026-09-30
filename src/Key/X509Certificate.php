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

namespace XmlDSig\Key;

use XmlDSig\Exception\InvalidKey;
use XmlDSig\Internal\OpenSsl;

final readonly class X509Certificate
{
    private function __construct(
        private \OpenSSLCertificate $certificate,
    ) {
    }

    /**
     * @throws InvalidKey
     */
    public static function fromPem(string $pem): self
    {
        $certificate = \openssl_x509_read($pem);
        if ($certificate === false) {
            throw InvalidKey::unreadable('certificate', OpenSsl::lastError());
        }

        return new self($certificate);
    }

    /**
     * @throws InvalidKey
     */
    public static function fromDer(string $der): self
    {
        return self::fromPem(
            "-----BEGIN CERTIFICATE-----\n"
            . \chunk_split(\base64_encode($der), 64, "\n")
            . "-----END CERTIFICATE-----\n",
        );
    }

    /**
     * @throws InvalidKey
     */
    public static function fromFile(string $path): self
    {
        return self::fromPem(OpenSsl::readFile($path));
    }

    public function toDer(): string
    {
        if (!\openssl_x509_export($this->certificate, $pem)) {
            throw InvalidKey::unreadable('certificate', OpenSsl::lastError());
        }

        $body = (string) \preg_replace('/-----[^-]+-----|\s+/', '', $pem);

        return (string) \base64_decode($body, true);
    }

    public function publicKey(): PublicKey
    {
        $key = \openssl_pkey_get_public($this->certificate);
        if ($key === false) {
            throw InvalidKey::unreadable('certificate public key', OpenSsl::lastError());
        }

        return PublicKey::fromHandle($key);
    }

    /**
     * Binary SHA-256 fingerprint of the DER encoding.
     */
    public function fingerprint(): string
    {
        return \hash('sha256', $this->toDer(), true);
    }

    public function equals(self $other): bool
    {
        return \hash_equals($this->fingerprint(), $other->fingerprint());
    }
}
