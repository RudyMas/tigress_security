<?php

namespace Tigress;

use Random\RandomException;

/**
 * Class Security (PHP version 8.3)
 *
 * @author Rudy Mas <rudy.mas@rudymas.be>
 * @copyright 2024, rudymas.be. (http://www.rudymas.be/)
 * @license https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version 1.1.2
 * @lastmodified 2024-10-21
 * @package Tigress\Security
 */
class Security
{
    private static array $sites = ['localhost'];

    /**
     * Get the version of the class
     *
     * @return string
     */
    public static function version(): string
    {
        return '1.1.2';
    }

    public function __construct()
    {
        $sites = [];
        foreach (CONFIG->servers as $server => $serverType) {
            $sites[] = $server;
        }
        $this->setSites($sites);
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
        $referenceOkay = self::pathMatches($_SERVER['HTTP_REFERER'], $referencePaths);

        if (!$referenceOkay) {
            header('HTTP/1.0 403 Forbidden');
            exit;
        }
    }

    /**
     * Check if the request comes from a certain path
     *
     * @param $urlPath
     * @param $referencePaths
     * @return bool
     */
    private static function pathMatches($urlPath, $referencePaths): bool
    {
        // Break down the URL path into an array
        $referer = parse_url($urlPath);
        $referees = explode('/', trim($referer['path'], '/')); // Trimming leading/trailing slashes

        // Loop through each possible reference path
        foreach ($referencePaths as $referencePath) {
            // Break down the reference path into an array
            $paths = explode('/', trim($referencePath, '/'));

            // Check if the paths match
            if (self::pathsMatch($referees, $paths)) {
                return true;
            }
        }

        return false; // If no path matches
    }

    /**
     * Check if the URL path matches the reference path
     *
     * @param $referees
     * @param $paths
     * @return bool
     */
    private static function pathsMatch($referees, $paths): bool
    {
        // If the reference path is shorter than the URL path and doesn't contain a wildcard, it's not a match
        if (count($paths) < count($referees)) {
            return false;
        }

        // Loop through each segment of the reference path
        foreach ($paths as $index => $segment) {
            // If wildcard (*), this segment matches anything (or nothing)
            if ($segment === '*') {
                continue;
            }

            // Check if the URL path has a corresponding segment to compare
            if (!isset($referees[$index]) || $referees[$index] !== $segment) {
                return false;
            }
        }

        return true;
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
    public static function setSites(array $sites): void
    {
        self::$sites = $sites;
    }
}