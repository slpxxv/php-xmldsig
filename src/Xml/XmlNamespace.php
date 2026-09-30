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

namespace XmlDSig\Xml;

enum XmlNamespace: string
{
    case Ds = 'http://www.w3.org/2000/09/xmldsig#';
    case Ec = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    public function prefix(): string
    {
        return match ($this) {
            self::Ds => 'ds',
            self::Ec => 'ec',
        };
    }

    public function qualify(string $localName): string
    {
        return $this->prefix() . ':' . $localName;
    }
}
