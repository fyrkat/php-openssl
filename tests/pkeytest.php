<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl\tests;

use fyrkat\openssl\PublicKey;
use fyrkat\openssl\PrivateKey;

use PHPUnit\Framework\TestCase;

class PublicKeyTest extends TestCase
{
	/** @var PublicKey */
	private $pubkey;

	/** @var string */
	private $pubkeyData;

	/** @var PublicKey */
	private $privkey;

	/** @var string */
	private $privkeyData;

	/** @var string */
	private $pubkeyfile = __DIR__ . \DIRECTORY_SEPARATOR . 'certs' . \DIRECTORY_SEPARATOR . 'selfsignedx509-pubkey.pem';

	/** @var string */
	private $privkeyfile = __DIR__ . \DIRECTORY_SEPARATOR . 'certs' . \DIRECTORY_SEPARATOR . 'selfsignedx509-privkey.pem';

	public function setUp(): void
	{
		$this->pubkeyData = \file_get_contents( $this->pubkeyfile );
		$this->pubkey = new PublicKey( $this->pubkeyData );
		$this->privkeyData = \file_get_contents( $this->privkeyfile );
		$this->privkey = new PrivateKey( $this->privkeyData );
	}

	public function testPublicKey(): void
	{
		$details = $this->pubkey->getDetails();
		$this->assertSame( $this->pubkeyData, $details['key'] );
		$this->assertSame( ['bits', 'key', 'rsa', 'type'], \array_keys( $details ) );
		$this->assertSame( ['n', 'e'], \array_keys( $details['rsa'] ) );
		$this->assertSame( 'af2d025eaaa92ddfcd2b578cbe72fa1ab9c3df06', $this->pubkey->fingerprint( 'sha1' ) );
	}

	public function testConstructor(): void
	{
		// Created using a file path instead of feeding the certificate data
		$pubkey = new PublicKey( "file://{$this->pubkeyfile}" );
		$this->assertEquals( $this->pubkey->getPublicKeyPem(), $pubkey->getPublicKeyPem() );
	}

	public function testConstructorError(): void
	{
		$this->expectException( 'fyrkat\openssl\OpenSSLException' );
		$pubkey = new PublicKey( "file:/{$this->pubkeyfile}" );
	}

	public function testMatchingKey(): void
	{
		$this->assertTrue( $this->pubkey->checkPrivateKey( $this->privkey ) );
	}

	public function testExtractPublicKey(): void
	{
		$pubkey = $this->privkey->getPublicKey();
		$pem1 = '';
		$pem2 = '';
		$this->pubkey->export( $pem1 );
		$pubkey->export( $pem2 );
		$this->assertSame( $pem1, $pem2 );
	}
}
