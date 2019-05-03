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
	public function testToString(): void
	{
		$dn = new DN( ['CN' => 'fyrkat\x509 test'] );
		$this->assertSame( '/CN=fyrkat\x509 test', $dn->__toString() );
	}
}
