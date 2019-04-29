<?php declare( strict_types=1 );

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

class DN
{
	/** @var array<string,string|array<string>> */
	private $dnData;

	/** @param array<string,string|array<string>> $dn */
	public function __construct( array $dn )
	{
		$this->dnData = $dn;
	}

	/** @return array<string,string|array<string>> */
	public function getArray(): array
	{
		return $this->dnData;
	}
}
