<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl\tests;

use fyrkat\openssl\DN;

use PHPUnit\Framework\TestCase;

class DNTest extends TestCase
{
	public function testCommonName(): void
	{
		$dn = new DN( ['CN' => 'fyrkat\x509 test'] );
		$this->assertSame( 'CN=fyrkat\\\\x509 test', $dn->__toString() );
	}

	/**
	 * Test the example string from the PHP documentation
	 *
	 * @see http://php.net/openssl_csr_new
	 */
	public function testPHPDocumentation(): void
	{
		$dn = new DN( [
			'countryName' => 'GB',
			'stateOrProvinceName' => 'Somerset',
			'localityName' => 'Glastonbury',
			'organizationName' => 'The Brain Room Limited',
			'organizationalUnitName' => 'PHP Documentation Team',
			'commonName' => 'Wez Furlong',
			'emailAddress' => 'wez@example.com',
		] );
		$this->assertSame(
				'emailAddress=wez@example.com, C=GB, ST=Somerset, L=Glastonbury, O=The Brain Room Limited, OU=PHP Documentation Team, CN=Wez Furlong',
				$dn->__toString()
			);
	}

	/**
	 * Test the example string from the PHP documentation
	 *
	 * @see http://php.net/openssl_csr_new
	 */
	public function testWrongArray(): void
	{
		$this->expectException( 'DomainException' );
		$dn = new DN( [[
			'countryName' => 'GB',
			'stateOrProvinceName' => 'Somerset',
			'localityName' => 'Glastonbury',
			'organizationName' => 'The Brain Room Limited',
			'organizationalUnitName' => 'PHP Documentation Team',
			'commonName' => 'Wez Furlong',
			'emailAddress' => 'wez@example.com',
		]] );
	}
}
