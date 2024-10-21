<?php

namespace Tigress;

use Random\RandomException;

/**
 * Class Security (PHP version 8.3)
 *
 * @author Rudy Mas <rudy.mas@rudymas.be>
 * @copyright 2024, rudymas.be. (http://www.rudymas.be/)
 * @license https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version 1.1.0
 * @lastmodified 2024-10-10
 * @package Tigress\Security
 */
class Security
{
    private array $sites = ['localhost'];

    /**
     * Get the version of the class
     *
     * @return string
     */
    public static function version(): string
    {
        return '1.1.0';
    }

    /**
     * Check if the request comes from the website
     *
     * @return void
     */
    public static function checkAccess(): void
    {
        if (isset($_SERVER['HTTP_REFERER'])) {
            $referer = parse_url($_SERVER['HTTP_REFERER']);
            if (!in_array($referer['host'], self::$sites)) {
                header('HTTP/1.0 403 Forbidden');
                exit;
            }
        } else {
            header('HTTP/1.0 403 Forbidden');
            exit;
        }
    }

    /**
     * Check if the request comes from a certain path
     *
     * @param array $referencePaths
     * @return void
     */
    public static function checkReferer(array $referencePaths): void
    {
        $referenceOkay = false;
        foreach ($referencePaths as $referencePath) {
            if (isset($_SERVER['HTTP_REFERER'])) {
                $referer = parse_url($_SERVER['HTTP_REFERER']);
                $referees = explode('/', $referer['path']);
                $paths = explode('/', $referencePath);
                for ($i = 0; $i < count($paths) && $i < count($referees); $i++) {
                    if ($paths[$i] === $referees[$i] || $paths[$i] === '*') {
                        $referenceOkay = true;
                    }
                }
            }
        }

        if (!$referenceOkay) {
            header('HTTP/1.0 403 Forbidden');
            exit;
        }
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

    /**
     * Set the sites
     *
     * @param array $sites
     * @return void
     */
    public function setSites(array $sites): void
    {
        $this->sites = $sites;
    }
}