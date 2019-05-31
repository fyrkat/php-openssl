<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

trait ResourceOwner
{
	/**
	 * @var resource
	 */
	private $resource;

	/**
	 * @return resource
	 */
	public function getResource()
	{
		return $this->resource;
	}

	/**
	 * @param resource $resource
	 * @psalm-suppress RedundantConditionGivenDocblockType
	 */
	protected function setResource( $resource ): void
	{
		\assert(
				\is_resource( $resource ),
				'$resource is a resource'
			);
		$this->resource = $resource;
	}
}
