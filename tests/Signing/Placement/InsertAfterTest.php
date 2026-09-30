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

namespace XmlDSigTests\Signing\Placement;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use XmlDSig\Signing\Placement\InsertAfter;

#[CoversClass(InsertAfter::class)]
final class InsertAfterTest extends TestCase
{
    public function testRejectsDetachedSibling(): void
    {
        $document = new \DOMDocument();

        $this->expectException(\LogicException::class);

        (new InsertAfter($document->createElement('orphan')))->place($document->createElement('signature'));
    }
}
