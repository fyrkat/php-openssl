<?php declare(strict_types=1);

/*
 * This file is part of fyrkat\openssl; a PHP class wrapper around openssl_* functions
 *
 * Copyright: 2019, Jørn Åne de Jong <@jornane.no>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace fyrkat\openssl;

/**
 * Common class for wrapping around OpenSSL resources
 *
 * The class provides getResource() and setResource(resource).
 */
abstract class OpenSSLResource
{
	/**
	 * @var resource An OpenSSL resource
	 */
	private $resource;

	/**
	 * Get the internal OpenSSL resource
	 *
	 * @return resource The OpenSSL resource
	 */
	public function getResource()
	{
		return $this->resource;
	}

	/**
	 * Set the internal OpenSSL resource
	 *
	 * @param resource $resource
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
