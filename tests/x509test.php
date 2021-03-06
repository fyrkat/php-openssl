<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl\tests;

use DateTimeImmutable;

use fyrkat\openssl\DN;
use fyrkat\openssl\PrivateKey;
use fyrkat\openssl\X509;

use PHPUnit\Framework\TestCase;

class x509Test extends TestCase
{
	/** @var X509 */
	private $x509;

	/** @var string */
	private $x509File = __DIR__ . \DIRECTORY_SEPARATOR . 'certs' . \DIRECTORY_SEPARATOR . 'selfsignedx509-cert.pem';

	/** @var string */
	private $privKeyFile = __DIR__ . \DIRECTORY_SEPARATOR . 'certs' . \DIRECTORY_SEPARATOR . 'selfsignedx509-privkey.pem';

	/** @var string */
	private $pubKeyFile = __DIR__ . \DIRECTORY_SEPARATOR . 'certs' . \DIRECTORY_SEPARATOR . 'selfsignedx509-pubkey.pem';

	/** @var string */
	private $x509Pem;

	/** @var string */
	private $privKeyPem;

	/** @var string */
	private $pubKeyPem;

	public function setUp(): void
	{
		$this->x509Pem = \file_get_contents( $this->x509File );
		$this->privKeyPem = \file_get_contents( $this->privKeyFile );
		$this->pubKeyPem = \file_get_contents( $this->pubKeyFile );
		$this->x509 = new X509( $this->x509Pem );
	}

	public function testCheckPrivateKey(): void
	{
		$this->assertTrue( $this->x509->checkPrivateKey( new PrivateKey( $this->privKeyPem ) ) );
	}

	public function testExport(): void
	{
		$this->assertSame( $this->x509Pem, $this->x509->getX509Pem() );
	}

	public function testFingerprint(): void
	{
		$this->assertSame( '85c59c149b62e155d211a410ce7c78edc5271e4c', $this->x509->fingerprint( 'sha1', false ) );
		$this->assertSame( \hex2bin( '85c59c149b62e155d211a410ce7c78edc5271e4c' ), $this->x509->fingerprint( 'sha1', true ) );
	}

	public function testPublicKey(): void
	{
		$key = $this->x509->getPublicKey();
		$details = $key->getDetails();
		$this->assertSame( $this->pubKeyPem, $details['key'] );
		$this->assertSame( ['bits', 'key', 'rsa', 'type'], \array_keys( $details ) );
		$this->assertSame( ['n', 'e'], \array_keys( $details['rsa'] ) );
	}

	public function testCheckPurpose(): void
	{
		$this->assertTrue( $this->x509->checkPurpose( X509::PURPOSE_ANY, [$this->x509File] ) );
	}

	public function testRawParse(): void
	{
		$this->assertEquals( require __DIR__ . '/certs/selfsignedx509-parsed.php', $this->x509->parse() );
	}

	public function testParse(): void
	{
		$this->assertSame( 'a30f7f23', $this->x509->getHash() );
		$this->assertSame( '17650764870988449858', $this->x509->getSerialNumber() );
		$this->assertSame( 'F4F41D21E535C842', $this->x509->getSerialNumberHex() );
		$this->assertEquals( new DN( ['CN' => 'fyrkat\x509 test'] ), $this->x509->getSubject( false ) );
		$this->assertEquals( new DN( ['commonName' => 'fyrkat\x509 test'] ), $this->x509->getSubject( true ) );
		$this->assertEquals( new DN( ['CN' => 'fyrkat\x509 test'] ), $this->x509->getIssuerSubject( false ) );
		$this->assertEquals( new DN( ['commonName' => 'fyrkat\x509 test'] ), $this->x509->getIssuerSubject( true ) );
		$this->assertSame( '/CN=fyrkat\x509 test', $this->x509->getName() );
		$this->assertSame( 0, $this->x509->getVersion() );
		$this->assertEquals( new DateTimeImmutable( '2019-01-01 22:51:47' ), $this->x509->getValidFrom() );
		$this->assertEquals( new DateTimeImmutable( '3018-05-04 22:51:47' ), $this->x509->getValidTo() );
		$this->assertSame( [1, 2, 3, 4, 5, 6, 7, 8, 9], \array_keys( $this->x509->getRawPurposes() ) );
		$this->assertSame( [], $this->x509->getRawExtensions() );
	}

	public function testConstructor(): void
	{
		// Created using a file path instead of feeding the certificate data
		$x509 = new X509( "file://{$this->x509File}" );
		$this->assertEquals( $this->x509->__toString(), $x509->__toString() );
	}

	public function testConstructorError(): void
	{
		$this->expectException( 'fyrkat\openssl\OpenSSLException' );
		$x509 = new X509( "file:/{$this->x509File}" );
	}

	public function testConstructorFuzz(): void
	{
		$this->expectException( 'fyrkat\openssl\OpenSSLException' );
		new X509( ':-)' );
	}

	public function testFingerprintFuzz(): void
	{
		$this->expectException( 'fyrkat\openssl\OpenSSLException' );
		$this->x509->fingerprint( ':-)', false );
	}

	public function testPurposeFuzz(): void
	{
		$this->expectException( 'fyrkat\openssl\OpenSSLException' );
		$this->x509->checkPurpose( -1, [], '/tmp/nonexistent' );
	}
}
