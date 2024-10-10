<?php

namespace Tigress;

use Random\RandomException;

/**
 * Class Security (PHP version 8.3)
 *
 * @author Rudy Mas <rudy.mas@rudymas.be>
 * @copyright 2024, rudymas.be. (http://www.rudymas.be/)
 * @license https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version 1.0.0
 * @lastmodified 2024-10-10
 * @package Tigress\Security
 */
class Security
{
    /**
     * Get the version of the class
     *
     * @return string
     */
    public static function version(): string
    {
        return '1.0.0';
    }

    /**
     * Create a random salt
     *
     * @return string
     * @throws RandomException
     */
    public function createSalt(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Create a hash from a password and a salt
     *
     * @param string $password
     * @param string $salt
     * @return string
     */
    public function createHash(string $password, string $salt): string
    {
        return hash('sha256', $password . $salt);
    }

    /**
     * Verify a hash
     *
     * @param string $password
     * @param string $salt
     * @param string $hash
     * @return bool
     */
    public function verifyHash(string $password, string $salt, string $hash): bool
    {
        return hash_equals($hash, $this->createHash($password, $salt));
    }
}