<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl\tests;

use fyrkat\openssl\PublicKey;

use PHPUnit\Framework\TestCase;

class PublicKeyTest extends TestCase
{
	/** @var PublicKey */
	private $pubkey;

	private $pubkeyData;

	/** @var string */
	private $pubkeyfile = __DIR__ . \DIRECTORY_SEPARATOR . 'certs' . \DIRECTORY_SEPARATOR . 'pubkey.pem';

	public function setUp(): void
	{
		$this->pubkeyData = \file_get_contents( $this->pubkeyfile );
		$this->pubkey = new PublicKey( $this->pubkeyData );
	}

	public function testPublicKey(): void
	{
		$details = $this->pubkey->getDetails();
		$this->assertSame( $this->pubkeyData, $details['key'] );
		$this->assertSame( ['bits', 'key', 'rsa', 'type'], \array_keys( $details ) );
		$this->assertSame( ['n', 'e'], \array_keys( $details['rsa'] ) );
	}
}
