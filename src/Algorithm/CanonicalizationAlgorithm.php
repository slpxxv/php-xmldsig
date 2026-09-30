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

enum CanonicalizationAlgorithm: string
{
    case Inclusive = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    case InclusiveWithComments = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    case Exclusive = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    case ExclusiveWithComments = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    public static function fromUri(string $uri): self
    {
        return self::tryFrom($uri) ?? throw UnsupportedAlgorithm::forUri($uri);
    }

    public function isExclusive(): bool
    {
        return $this === self::Exclusive || $this === self::ExclusiveWithComments;
    }

    public function withComments(): bool
    {
        return $this === self::InclusiveWithComments || $this === self::ExclusiveWithComments;
    }

    public function withoutComments(): self
    {
        return $this->isExclusive() ? self::Exclusive : self::Inclusive;
    }
}
