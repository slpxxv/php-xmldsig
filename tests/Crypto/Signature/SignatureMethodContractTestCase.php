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

namespace XmlDSigTests\Crypto\Signature;

use PHPUnit\Framework\TestCase;
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Crypto\Signature\SignatureMethod;
use XmlDSig\Exception\KeyAlgorithmMismatch;
use XmlDSig\Key\PrivateKey;

/**
 * Contract every SignatureMethod implementation must satisfy.
 */
abstract class SignatureMethodContractTestCase extends TestCase
{
    abstract protected function method(): SignatureMethod;

    abstract protected function algorithm(): SignatureAlgorithm;

    abstract protected function key(): PrivateKey;

    abstract protected function foreignKey(): PrivateKey;

    public function testSupportsItsAlgorithm(): void
    {
        self::assertTrue($this->method()->supports($this->algorithm()));
    }

    public function testSignatureVerifies(): void
    {
        $signature = $this->method()->sign('payload', $this->key(), $this->algorithm());

        self::assertTrue($this->method()->verify('payload', $signature, $this->key()->publicKey(), $this->algorithm()));
    }

    public function testTamperedDataDoesNotVerify(): void
    {
        $signature = $this->method()->sign('payload', $this->key(), $this->algorithm());

        $publicKey = $this->key()->publicKey();

        self::assertFalse($this->method()->verify('tampered', $signature, $publicKey, $this->algorithm()));
    }

    public function testGarbageSignatureDoesNotVerify(): void
    {
        self::assertFalse($this->method()->verify('payload', 'garbage', $this->key()->publicKey(), $this->algorithm()));
    }

    public function testRejectsKeyOfOtherType(): void
    {
        $this->expectException(KeyAlgorithmMismatch::class);

        $this->method()->sign('payload', $this->foreignKey(), $this->algorithm());
    }
}
