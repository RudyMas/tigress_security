<?php

namespace Tigress;

use Random\RandomException;
use Repository\SystemLockPagesRepo;
use Repository\UsersRepo;

/**
 * Class Security (PHP version 8.5)
 *
 * @author Rudy Mas <rudy.mas@rudymas.be>
 * @copyright 2024-2026, rudymas.be. (http://www.rudymas.be/)
 * @license https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version 2026.01.07.1
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
        return '2026.01.06';
    }

    public function __construct()
    {
        $sites = [];
        foreach (CONFIG->servers as $server => $serverType) {
            $sites[] = $server;
        }
        $this->setSites($sites);

        TRANSLATIONS->load(SYSTEM_ROOT . '/vendor/tigress/security/translations/translations.json');
    }

    /**
     * Check if the request comes from the website
     *
     * @param array|null $destinationPaths Set this to the paths you want to bypass
     * @return void
     */
    public function checkAccess(?array $destinationPaths = null): void
    {
        if (isset($_SERVER['HTTP_REFERER'])) {
            $referer = parse_url($_SERVER['HTTP_REFERER']);
            if (!in_array($referer['host'], $this->sites)) {
                header('HTTP/1.0 403 Forbidden');
                exit;
            }
        } else {
            if (isset($destinationPaths)) {
                if (!self::pathMatches($_SERVER['REQUEST_URI'], $destinationPaths)) {
                    header('HTTP/1.0 403 Forbidden');
                    exit;
                }
            } else {
                header('HTTP/1.0 403 Forbidden');
                exit;

            }
        }
    }

    /**
     *  Check if a page is locked
     *
     * @param string $resource
     * @param int $resourceId
     * @return bool
     */
    public function checkIfPageIsLocked(string $resource, int $resourceId): bool
    {
        $systemLockPageRepo = new SystemLockPagesRepo();

        $now = date('Y-m-d H:i:s');
        $expires = date('Y-m-d H:i:s', time() + 300);

        // delete expired locks
        $sql = "DELETE FROM system_lock_pages
                WHERE expires_at < :current_time";
        $systemLockPageRepo->deleteByQuery($sql, [
            ':current_time' => $now
        ]);

        $systemLockPageRepo->reset();
        $systemLockPageRepo->loadByPrimaryKey([
            'resource' => $resource,
            'resource_id' => $resourceId
        ]);

        if ($systemLockPageRepo->isEmpty()) {
            $systemLockPageRepo->new();
            $systemLockPage = $systemLockPageRepo->current();
            $systemLockPage->resource = $resource;
            $systemLockPage->resource_id = $resourceId;
            $systemLockPage->locked_by_user_id = $_SESSION['user']['id'] ?? null;
            $systemLockPage->locked_at = $now;
            $systemLockPage->expires_at = $expires;
            $systemLockPageRepo->save($systemLockPage);
            return false;
        }

        $systemLockPage = $systemLockPageRepo->current();

        if ($systemLockPage->expires_at < $now) {
            $systemLockPage->locked_by_user_id = $_SESSION['user']['id'] ?? null;
            $systemLockPage->locked_at = $now;
            $systemLockPage->expires_at = $expires;
            $systemLockPageRepo->save($systemLockPage);
            return false;
        }

        $usersRepo = new UsersRepo();
        $usersRepo->loadById($systemLockPage->locked_by_user_id);
        $user = $usersRepo->current();

        $infoMessage = __('This page is currently being edited by ');
        $infoMessage .= htmlspecialchars($user->first_name . ' ' . $user->last_name);
        $infoMessage .= __('. Please try again later.');
        $_SESSION['message'] = $infoMessage;

        return true;
    }

    /**
     * Check if the request comes from a certain path
     *
     * @param array $referencePaths
     * @return void
     */
    public function checkReferer(array $referencePaths): void
    {
        if (!isset($_SERVER['HTTP_REFERER'])) {
            header('HTTP/1.0 403 Forbidden');
            exit;
        }

        if (!self::pathMatches($_SERVER['HTTP_REFERER'], $referencePaths)) {
            header('HTTP/1.0 403 Forbidden');
            exit;
        }
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
     * Remove a page lock
     *
     * @param string $resource
     * @param int $resourceId
     * @return void
     */
    public function removePageLock(string $resource, int $resourceId): void
    {
        $systemLockPageRepo = new SystemLockPagesRepo();
        $systemLockPageRepo->deleteByPrimaryKey([
            'resource' => $resource,
            'resource_id' => $resourceId
        ]);
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
     * Check if the request comes from a certain path
     *
     * @param string $urlPath
     * @param array $referencePaths
     * @return bool
     */
    private function pathMatches(string $urlPath, array $referencePaths): bool
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
     * @param array $referees
     * @param array $paths
     * @return bool
     */
    private function pathsMatch(array $referees, array $paths): bool
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
}