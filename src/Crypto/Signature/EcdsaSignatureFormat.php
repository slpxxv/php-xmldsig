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

namespace XmlDSig\Crypto\Signature;

/**
 * Converts ECDSA signatures between OpenSSL's DER encoding and the
 * fixed-length r||s concatenation required by XMLDSig (RFC 4050, RFC 6931).
 *
 * @internal
 */
final class EcdsaSignatureFormat
{
    private const SEQUENCE = 0x30;
    private const INTEGER = 0x02;

    /**
     * @throws \InvalidArgumentException on malformed DER.
     */
    public static function derToRaw(string $der, int $coordinateLength): string
    {
        $offset = 0;
        self::expectTag($der, $offset, self::SEQUENCE);
        $sequenceLength = self::readLength($der, $offset);
        if ($offset + $sequenceLength !== \strlen($der)) {
            throw new \InvalidArgumentException('Invalid ECDSA signature: trailing or missing bytes.');
        }

        $r = self::readInteger($der, $offset, $coordinateLength);
        $s = self::readInteger($der, $offset, $coordinateLength);
        if ($offset !== \strlen($der)) {
            throw new \InvalidArgumentException('Invalid ECDSA signature: unexpected data after S.');
        }

        return $r . $s;
    }

    /**
     * @throws \InvalidArgumentException when the raw value has an odd length.
     */
    public static function rawToDer(string $raw): string
    {
        $length = \strlen($raw);
        if ($length === 0 || $length % 2 !== 0) {
            throw new \InvalidArgumentException('Invalid ECDSA signature: r||s must have an even length.');
        }

        $half = \intdiv($length, 2);
        $body = self::encodeInteger(\substr($raw, 0, $half)) . self::encodeInteger(\substr($raw, $half));

        return \chr(self::SEQUENCE) . self::encodeLength(\strlen($body)) . $body;
    }

    private static function readInteger(string $der, int &$offset, int $coordinateLength): string
    {
        self::expectTag($der, $offset, self::INTEGER);
        $length = self::readLength($der, $offset);
        $value = \substr($der, $offset, $length);
        if (\strlen($value) !== $length) {
            throw new \InvalidArgumentException('Invalid ECDSA signature: truncated integer.');
        }
        $offset += $length;

        $value = \ltrim($value, "\x00");
        if (\strlen($value) > $coordinateLength) {
            throw new \InvalidArgumentException('Invalid ECDSA signature: integer exceeds curve size.');
        }

        return \str_pad($value, $coordinateLength, "\x00", \STR_PAD_LEFT);
    }

    private static function expectTag(string $der, int &$offset, int $tag): void
    {
        if (!isset($der[$offset]) || \ord($der[$offset]) !== $tag) {
            throw new \InvalidArgumentException(\sprintf('Invalid ECDSA signature: expected tag 0x%02x.', $tag));
        }
        $offset++;
    }

    private static function readLength(string $der, int &$offset): int
    {
        if (!isset($der[$offset])) {
            throw new \InvalidArgumentException('Invalid ECDSA signature: missing length.');
        }

        $first = \ord($der[$offset++]);
        if ($first < 0x80) {
            return $first;
        }

        $bytes = $first & 0x7f;
        if ($bytes === 0 || $bytes > 2 || $offset + $bytes > \strlen($der)) {
            throw new \InvalidArgumentException('Invalid ECDSA signature: unsupported length encoding.');
        }

        $length = 0;
        for ($i = 0; $i < $bytes; $i++) {
            $length = ($length << 8) | \ord($der[$offset++]);
        }

        return $length;
    }

    private static function encodeInteger(string $value): string
    {
        $value = \ltrim($value, "\x00");
        if ($value === '' || (\ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }

        return \chr(self::INTEGER) . self::encodeLength(\strlen($value)) . $value;
    }

    private static function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return \chr($length);
        }

        $bytes = \ltrim(\pack('N', $length), "\x00");

        return \chr(0x80 | \strlen($bytes)) . $bytes;
    }
}
