# xmldsig

XML Digital Signature ([XMLDSig](https://www.w3.org/TR/xmldsig-core1/)) signing and verification for PHP,
built on `ext-dom` and `ext-openssl` only.

- RSA (PKCS#1 v1.5) and ECDSA (P-256/384/521, `r||s` encoded) with SHA-2
- Inclusive and exclusive C14N, enveloped signatures, `InclusiveNamespaces`
- Secure by default: SHA-1 rejected, duplicate IDs rejected, `ds:KeyInfo` never trusted blindly

## Installation

```bash
composer require slpxxv/php-xmldsig
```

## Signing

```php
use XmlDSig\Algorithm\SignatureAlgorithm;
use XmlDSig\Key\PrivateKey;
use XmlDSig\Key\X509Certificate;
use XmlDSig\KeyInfo\X509DataSource;
use XmlDSig\Signing\Placement\AppendToElement;
use XmlDSig\Signing\ReferenceDefinition;
use XmlDSig\Signing\SigningKey;
use XmlDSig\Signing\SigningRequest;
use XmlDSig\XmlDSig;

$document = new DOMDocument();
$document->load('invoice.xml');

XmlDSig::signer()->sign($document, new SigningRequest(
    signingKey: new SigningKey(PrivateKey::fromFile('key.pem', 'passphrase'), SignatureAlgorithm::RsaSha256),
    references: [ReferenceDefinition::enveloped('#invoice-1')],
    placement: new AppendToElement($document->documentElement),
    keyInfo: new X509DataSource(X509Certificate::fromFile('cert.pem')),
));
```

Use `InsertAfter` to place the signature after a given element (e.g. `saml:Issuer`), or implement
`SignaturePlacement` for anything else.

## Verifying

```php
use XmlDSig\Key\X509Certificate;
use XmlDSig\Verification\KeyResolver\PinnedCertificateResolver;
use XmlDSig\XmlDSig;

$verified = XmlDSig::verifier(new PinnedCertificateResolver(X509Certificate::fromFile('partner.pem')))
    ->verify($document);

// Only trust what the signature actually covers.
if (!$verified->covers($invoiceElement)) {
    throw new RuntimeException('Invoice is not signed.');
}
```

`verify()` throws on any failure, so there is no boolean to forget to check. Catch
`XmlDSig\Exception\XmlDSigException` to handle every library error.

Key resolvers:

| Resolver | Use when |
|---|---|
| `StaticKeyResolver` | You know the signer's public key up front |
| `PinnedCertificateResolver` | The document embeds a certificate that must match one you trust |
| your own `KeyResolver` | You need PKI chain validation, a key store, HSM lookup, ... |

## Architecture

```
Signing/        use case: XmlSigner, SigningRequest, placements
Verification/   use case: XmlVerifier, key resolvers, VerifiedSignature
Reference/      URI -> node -> digest (ID lookup, duplicate ID detection)
Transform/      transform pipeline and registry (enveloped signature, C14N)
Canonicalization/, Crypto/, Key/, KeyInfo/
Algorithm/      algorithm enums and AlgorithmPolicy
Model/          immutable XMLDSig model, no DOM
Xml/            model <-> DOM serializer and parser
XmlDSig.php     composition root with default wiring
```

Extension points are interfaces (`SignatureMethod`, `Transform`, `ReferenceResolver`, `KeyResolver`,
`SignaturePlacement`, `Canonicalizer`, `Digester`); wire custom implementations through the
constructors of `XmlSigner` and `XmlVerifier`.

## Development

```bash
composer test
composer lint-check
composer static-analysis
```

## Support

- [Issues](https://github.com/slpxxv/php-xmldsig/issues/)

## License

The MIT License (MIT). Please see [License](LICENSE) for more information.
