<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl\tests;

use fyrkat\openssl\DN;
use fyrkat\openssl\X509;
use fyrkat\openssl\Purpose;
use fyrkat\openssl\PublicKey;
use fyrkat\openssl\PrivateKey;

use PHPUnit\Framework\TestCase;

class x509Test extends TestCase
{
	/** @var X509 */
	private $x509;

	/** @var string */
	private $x509file = __DIR__ . \DIRECTORY_SEPARATOR . 'certs' . \DIRECTORY_SEPARATOR . 'selfsignedx509.pem';

	/** @var string */
	private $x509PubPem;

	/** @var string */
	private $x509PrivPem;

	public function setUp(): void
	{
		$data = \file_get_contents( $this->x509file );
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

	public function testCheckPurpose(): void
	{
		$this->assertTrue( $this->x509->checkPurpose( Purpose::ANY, [$this->x509file] ) );
	}

	public function testRawParse(): void
	{
		$this->assertEquals( require __DIR__ . '/certs/selfsignedx509-parsed.php', $this->x509->parse()->getRawArray() );
	}

	public function testParse(): void
	{
		$this->assertSame( 'a30f7f23', $this->x509->parse()->getHash() );
		$this->assertSame( '17650764870988449858', $this->x509->parse()->getSerialNumber() );
		$this->assertSame( 'F4F41D21E535C842', $this->x509->parse()->getSerialNumberHex() );
		$this->assertEquals( new DN( ['CN' => 'fyrkat\x509 test'] ), $this->x509->parse( false )->getSubject() );
		$this->assertEquals( new DN( ['commonName' => 'fyrkat\x509 test'] ), $this->x509->parse( true )->getSubject() );
		$this->assertEquals( new DN( ['CN' => 'fyrkat\x509 test'] ), $this->x509->parse( false )->getIssuerSubject() );
		$this->assertEquals( new DN( ['commonName' => 'fyrkat\x509 test'] ), $this->x509->parse( true )->getIssuerSubject() );
		$this->assertSame( '/CN=fyrkat\x509 test', $this->x509->parse()->getName() );
		$this->assertSame( 0, $this->x509->parse()->getVersion() );
		$this->assertEquals( new \DateTimeImmutable( '2019-01-01 22:51:47' ), $this->x509->parse()->getValidFrom() );
		$this->assertEquals( new \DateTimeImmutable( '3018-05-04 22:51:47' ), $this->x509->parse()->getValidTo() );
		$this->assertEquals( [], $this->x509->parse()->getExtensions() );
	}
}
