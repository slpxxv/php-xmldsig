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

namespace XmlDSig\Transform;

use XmlDSig\Exception\TransformFailed;

/**
 * Removes the enclosing ds:Signature from the node-set (XMLDSig 6.6.4).
 */
final class EnvelopedSignatureTransform implements Transform
{
    public function apply(TransformData $data, ?\DOMElement $signature): TransformData
    {
        if (!$data->isNodeSet()) {
            throw TransformFailed::because('the enveloped signature transform requires a node-set.');
        }

        return $signature === null ? $data : $data->excluding($signature);
    }
}
