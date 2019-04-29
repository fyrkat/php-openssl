<?php declare( strict_types=1 );

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl\tests;

use fyrkat\openssl\X509;
use fyrkat\openssl\PublicKey;
use fyrkat\openssl\PrivateKey;

use PHPUnit\Framework\TestCase;

class x509Test extends TestCase
{
	private $x509;

	private $x509PubPem;

	public function setUp(): void
	{
		$data = \file_get_contents( __DIR__ . \DIRECTORY_SEPARATOR . 'certs' . \DIRECTORY_SEPARATOR . 'selfsignedx509.pem' );
		$this->x509 = new X509( $data );
		\preg_match( '/-----BEGIN CERTIFICATE-----\n.*\n-----END CERTIFICATE-----\\n/ms', $data, $matches );
		$this->x509PubPem = $matches[0];
		\preg_match( '/-----BEGIN PRIVATE KEY-----\n.*\n-----END PRIVATE KEY-----\\n/ms', $data, $matches );
		$this->x509PrivPem = $matches[0];
	}

	public function testCheckPrivateKey(): void
	{
		$this->assertTrue( $this->x509->checkPrivateKey( new PrivateKey( $this->x509PrivPem ) ) );
	}

	public function testExport(): void
	{
		$out = '';
		$this->x509->export( $out );
		$this->assertSame( $this->x509PubPem, $out );
	}

	public function testFingerprint(): void
	{
		$this->assertSame( '85c59c149b62e155d211a410ce7c78edc5271e4c', $this->x509->fingerprint( 'sha1', false ) );
		$this->assertSame( \hex2bin( '85c59c149b62e155d211a410ce7c78edc5271e4c' ), $this->x509->fingerprint( 'sha1', true ) );
	}

	public function testPublicKey(): void
	{
		$key = new PublicKey( $this->x509 );
		$details = $key->getDetails();
		$data = \file_get_contents( __DIR__ . \DIRECTORY_SEPARATOR . 'certs' . \DIRECTORY_SEPARATOR . 'selfsignedpubkey.pem' );
		$this->assertSame( $data, $details['key'] );
		$this->assertSame( ['bits', 'key', 'rsa', 'type'], \array_keys( $details ) );
		$this->assertSame( ['n', 'e'], \array_keys( $details['rsa'] ) );
	}
}
