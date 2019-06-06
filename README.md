# Classes around openssl_* functions

This project provides classes around openssl_* functions in order to make
working with keys and certificates a bit more palable.  It is still a work
in progress.  Patches and bug reports welcome.


## Requirements

* PHP >=7.1
* Make
* (for first setup) internet connection


## Usage

Make sure that you use
[strict types](https://www.php.net/manual/en/functions.arguments.php#functions.arguments.type-declaration.strict)
in your code!

```php
<?php declare(strict_types=1);
```

### Self-sign

In order to make a self-signed CA, you need a key.

```php
$caPrivKey = new PrivateKey( new OpenSSLConfig( OpenSSLConfig::KEY_EC ) );
// Instead of OpenSSLConfig::KEY_EC you could use OpenSSLConfig::KEY_RSA.
```

From this key we will make a signing request.

```php
$caCsr = CSR::generate(
		new DN( ['CN' => 'fyrkat example CA'] ),
		$caPrivKey
	);
```

This request can now be self-signed.

```php
$caCertificate = $caCsr->sign( null, $caPrivKey, 18250, new OpenSSLConfig( OpenSSLConfig::X509_CA ) );
// We need the same $caPrivKey again because self-sign means you sign with your own key.
// OpenSSLConfig::X509_CA means that the resulting certificate is to be used as a CA.
// Other options are OpenSSLConfig::X509_SERVER and OpenSSLConfig::X509_CLIENT.
```

### Sign with own CA

If you already have your own CA, import it.

```php
// Update these three lines to your own liking.
$caPrivPem = getMyPrivateKeyPemFromSomewhere();
$caPrivPemPassphrase = 'supersecret'; // or null if no passphrase.
$caCertificatePem = getMyPrivateKeyPemFromSomewhere();

$caPrivKey = new PrivateKey( $caPrivPem, $passphrase );
$caCertificate = new X509( $caCertificatePem );
```

Now we have `$caPrivKey` and `$caCertificate` to work with.

```php
$serverPrivKey = new PrivateKey( new OpenSSLConfig( OpenSSLConfig::KEY_EC ) );
// Instead of OpenSSLConfig::KEY_EC you could use OpenSSLConfig::KEY_RSA.
$serverCsr = CSR::generate(
		new DN( ['CN' => 'example.com'] ),
		$serverPrivKey
	);
$serverCertificate = $caCsr->sign( $caCertificate, $caPrivKey, 1095, new OpenSSLConfig( OpenSSLConfig::X509_SERVER ) );
// Using $caCertificate ensures the resulting certificate is signed by $caCertificate, instead of being self-signed.
// OpenSSLConfig::X509_SERVER indicates that this will be a server certificate.
```

We can also make a client certificate.

```php
$clientPrivKey = new PrivateKey( new OpenSSLConfig( OpenSSLConfig::KEY_EC ) );
$clientCsr = CSR::generate(
		new DN( ['CN' => 'jornane@example.com'] ),
		$clientPrivKey
	);
$clientCertificate = $caCsr->sign( $caCertificate, $caPrivKey, 1095, new OpenSSLConfig( OpenSSLConfig::X509_CLIENT ) );
```

### Retrieving PEM representations

Classes holding public key material have a `__toString()` method, which allows you to use them as strings.

```php
echo $serverCertificate; // PEM output
```

However, `PrivateKey` does not have this feature, to avoid accidentally leaking data.
All classes have a function to get a PEM string.

```php
$caCertificatePem = $caCertificate->getX509Pem();
$serverCertificatePem = $serverCertificate->getX509Pem();
$serverPrivKeyPem = $serverPrivKey->getPrivateKeyPem( 'supersecret' );
// Instead of 'supersecret', you can use null if you don't want the output encrypted

// Additionally, you could export just the public key, but it might not be that useful
$pkPem = $serverCertificate->getPublicKey()->getPublicKeyPem();
```

## Testing

	make test


## Contributing

Before committing, run

	make camera-ready
