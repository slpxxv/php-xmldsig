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

namespace XmlDSig\Model;

use XmlDSig\Algorithm\DigestAlgorithm;

final readonly class Reference
{
    /**
     * @param string $digestValue Raw binary digest.
     * @param list<TransformSpec> $transforms
     */
    public function __construct(
        public string $uri,
        public DigestAlgorithm $digestAlgorithm,
        public string $digestValue,
        public array $transforms = [],
        public ?string $id = null,
        public ?string $type = null,
    ) {
    }
}
