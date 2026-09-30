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

namespace XmlDSig;

use XmlDSig\Algorithm\AlgorithmPolicy;
use XmlDSig\Canonicalization\DomCanonicalizer;
use XmlDSig\Crypto\Digest\HashDigester;
use XmlDSig\Crypto\Signature\SignatureMethodRegistry;
use XmlDSig\Reference\IdAttributes;
use XmlDSig\Reference\ReferenceDigester;
use XmlDSig\Reference\SameDocumentResolver;
use XmlDSig\Signing\SignedInfoFactory;
use XmlDSig\Signing\XmlSigner;
use XmlDSig\Transform\TransformPipeline;
use XmlDSig\Transform\TransformRegistry;
use XmlDSig\Verification\KeyResolver\KeyResolver;
use XmlDSig\Verification\SignatureLocator;
use XmlDSig\Verification\XmlVerifier;
use XmlDSig\Xml\SignatureParser;
use XmlDSig\Xml\SignatureSerializer;

/**
 * Composition root wiring the default implementations. Use the constructors directly for custom wiring.
 */
final class XmlDSig
{
    public static function signer(?AlgorithmPolicy $policy = null, ?IdAttributes $idAttributes = null): XmlSigner
    {
        $canonicalizer = new DomCanonicalizer();

        return new XmlSigner(
            new SignedInfoFactory(self::referenceDigester($idAttributes, $canonicalizer)),
            new SignatureSerializer(),
            $canonicalizer,
            SignatureMethodRegistry::default(),
            $policy ?? AlgorithmPolicy::secure(),
        );
    }

    public static function verifier(
        KeyResolver $keyResolver,
        ?AlgorithmPolicy $policy = null,
        ?IdAttributes $idAttributes = null,
    ): XmlVerifier {
        $canonicalizer = new DomCanonicalizer();

        return new XmlVerifier(
            new SignatureLocator(),
            new SignatureParser(),
            $keyResolver,
            $canonicalizer,
            SignatureMethodRegistry::default(),
            self::referenceDigester($idAttributes, $canonicalizer),
            $policy ?? AlgorithmPolicy::secure(),
        );
    }

    private static function referenceDigester(
        ?IdAttributes $idAttributes,
        DomCanonicalizer $canonicalizer,
    ): ReferenceDigester {
        return new ReferenceDigester(
            new SameDocumentResolver($idAttributes ?? IdAttributes::default()),
            new TransformPipeline(TransformRegistry::default($canonicalizer), $canonicalizer),
            new HashDigester(),
        );
    }
}
