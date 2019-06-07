<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl\tests;

use DateInterval;
use DateTimeImmutable;

use fyrkat\openssl\CSR;
use fyrkat\openssl\DN;
use fyrkat\openssl\OpenSSLConfig;
use fyrkat\openssl\OpenSSLKey;
use fyrkat\openssl\PrivateKey;
use fyrkat\openssl\X509;

use PHPUnit\Framework\TestCase;

class CATest extends TestCase
{
	/** @var X509 */
	private $ca;

	public function setUp(): void
	{
		$caConfig = new OpenSSLConfig( OpenSSLConfig::X509_CA );

		$this->ecKey = new PrivateKey( new OpenSSLConfig( OpenSSLConfig::KEY_EC ) );
		$this->rsaKey = new PrivateKey( new OpenSSLConfig( OpenSSLConfig::KEY_RSA ) );
		$csr = CSR::generate( new DN( ['CN' => 'unittest'] ), $this->ecKey );
		$this->ca = $csr->sign( null, $this->ecKey, 1, $caConfig );
		$this->caFile = \tempnam( \sys_get_temp_dir(), 'php_openssl_catest_ca_' );
		\file_put_contents( $this->caFile, $this->ca );
	}

	public function tearDown(): void
	{
		\unlink( $this->caFile );
	}

	public function testECConfig(): void
	{
		$csr = CSR::generate( new DN( ['CN' => 'example.com'] ), $this->ecKey );
		$x509 = $csr->sign( null, $this->ecKey, 1, new OpenSSLConfig( OpenSSLConfig::X509_SERVER ) );
		$this->assertSame( OpenSSLKey::KEYTYPE_EC, $x509->getPublicKey()->getType() );
		$this->assertSame( 256, $x509->getPublicKey()->getBits() );
		$this->assertSame( 'ecdsa-with-SHA256', $x509->getSignatureType() );
	}

	public function testRSAConfig(): void
	{
		$csr = CSR::generate( new DN( ['CN' => 'example.com'] ), $this->rsaKey );
		$x509 = $csr->sign( null, $this->rsaKey, 1, new OpenSSLConfig( OpenSSLConfig::X509_SERVER ) );
		$this->assertSame( OpenSSLKey::KEYTYPE_RSA, $x509->getPublicKey()->getType() );
		$this->assertSame( 2048, $x509->getPublicKey()->getBits() );
		$this->assertSame( 'RSA-SHA256', $x509->getSignatureType() );
	}

	public function testSign(): void
	{
		$caConfig = new OpenSSLConfig( OpenSSLConfig::X509_SERVER );

		$csr = CSR::generate( new DN( ['CN' => 'example.com'] ), $this->ecKey );
		$signed = $csr->sign( $this->ca, $this->ecKey, 1, $caConfig );
		$this->assertSame(
				$this->ca->getSubject()->getArray(),
				$signed->getIssuerSubject()->getArray()
			);
		$this->assertTrue( $signed->checkPurpose( X509::PURPOSE_SSL_SERVER, [$this->caFile] ) );
		$this->assertFalse( $signed->checkPurpose( X509::PURPOSE_SSL_CLIENT, [$this->caFile] ) );
	}

	public function testFuture(): void
	{
		$future = ( new DateTimeImmutable() )->add( new DateInterval('P1D') );
		$this->assertSame( 1, CSR::dateToDays( $future ) );
	}

	public function testPast(): void
	{
		$this->expectException( 'DomainException' );
		$past = ( new DateTimeImmutable() )->sub( new DateInterval('P1D') );
		CSR::dateToDays( $past );
	}

	public function testTooFewBitsConfig(): void
	{
		$this->expectException( 'DomainException' );
		$config = new OpenSSLConfig( ['private_key_bits' => 256] );
		$key = new PrivateKey( $config );
	}
}
