<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl\tests;

use fyrkat\openssl\DN;
use fyrkat\openssl\CSR;
use fyrkat\openssl\PrivateKey;
use PHPUnit\Framework\TestCase;

use fyrkat\openssl\OpenSSLConfig;

class ReadmeMDTest extends TestCase
{
	public function testReadme(): void
	{
		$caPrivKey = new PrivateKey( new OpenSSLConfig( OpenSSLConfig::KEY_EC ) );
		$caCsr = CSR::generate(
				new DN( ['CN' => 'fyrkat example CA'] ),
				$caPrivKey
			);
		$caCertificate = $caCsr->sign( null, $caPrivKey, 18250, new OpenSSLConfig( OpenSSLConfig::X509_CA ) );

		$serverPrivKey = new PrivateKey( new OpenSSLConfig( OpenSSLConfig::KEY_EC ) );
		$serverCsr = CSR::generate(
				new DN( ['CN' => 'example.com'] ),
				$serverPrivKey
			);
		$serverCertificate = $caCsr->sign( $caCertificate, $caPrivKey, 1095, new OpenSSLConfig( OpenSSLConfig::X509_SERVER ) );

		$clientPrivKey = new PrivateKey( new OpenSSLConfig( OpenSSLConfig::KEY_EC ) );
		$clientCsr = CSR::generate(
				new DN( ['CN' => 'jornane@example.com'] ),
				$clientPrivKey
			);
		$clientCertificate = $caCsr->sign( $caCertificate, $caPrivKey, 1095, new OpenSSLConfig( OpenSSLConfig::X509_CLIENT ) );

		$caCertificatePem = $caCertificate->getX509Pem();
		$serverCertificatePem = $serverCertificate->getX509Pem();
		$serverPrivKeyPem = $serverPrivKey->getPrivateKeyPem( 'supersecret' );

		$pkPem = $serverCertificate->getPublicKey()->getPublicKeyPem();

		$this->assertSame(
				$caCertificate->getSubject()->getArray(),
				$clientCertificate->getIssuerSubject()->getArray()
			);
		$this->assertSame(
				$caCertificate->getSubject()->getArray(),
				$serverCertificate->getIssuerSubject()->getArray()
			);
	}
}
