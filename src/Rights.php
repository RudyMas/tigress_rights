<?php

namespace Tigress;

use Repository\systemRightsRepo;

/**
 * Class Rights (PHP version 8.3)
 *
 * @author       Rudy Mas <rudy.mas@rudymas.be>
 * @copyright    2024, Rudy Mas (http://rudymas.be/)
 * @license      https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version      1.4.2
 * @lastmodified 2024-11-08
 * @package      Tigress
 */
class Rights
{
    private array $accessList = [];

    /**
     * Get the version of the Rights
     *
     * @return string
     */
    public static function version(): string
    {
        return '1.4.2';
    }

    /**
     * Set the access list
     *
     * @param $routes
     * @return void
     */
    public function setRights($routes): void
    {
        // First, build the access list for paths that explicitly have rights
        foreach (ROUTES->routes as $route) {
            $path = preg_replace('/{[^}]+}/', '*', $route->path);

            // Add level-rights, special-rights, and special-rights-default if available
            $this->accessList[$path] = [
                'level_rights' => $route->level_rights ?? []
            ];

            if (isset($route->special_rights)) {
                $this->accessList[$path]['special_rights'] = $route->special_rights;
            }

            if (isset($route->special_rights_default)) {
                $this->accessList[$path]['special_rights_default'] = $route->special_rights_default;
            }
        }

        // Now inherit rights from the first parent that has them defined
        foreach (ROUTES->routes as $route) {
            $path = preg_replace('/{[^}]+}/', '*', $route->path);

            // Only inherit rights if level-rights, special-rights, and special-rights-default are empty
            if (empty($this->accessList[$path]['level_rights']) &&
                empty($this->accessList[$path]['special_rights']) &&
                empty($this->accessList[$path]['special_rights_default'])
            ) {
                $parentRights = $this->getFirstParentWithRights($path);
                if ($parentRights) {
                    $this->accessList[$path]['level_rights'] = $parentRights['level_rights'];
                    if (isset($parentRights['special_rights'])) {
                        $this->accessList[$path]['special_rights'] = $parentRights['special_rights'];
                    }
                    if (isset($parentRights['special_rights_default'])) {
                        $this->accessList[$path]['special_rights_default'] = $parentRights['special_rights_default'];
                    }
                }
            }
        }
    }

    /**
     * Get the parent rights
     *
     * @param $path
     * @param $accessList
     * @return mixed|null
     */
    public function getParentRights($path, $accessList): mixed
    {
        $parts = explode('/', trim($path, '/'));
        array_pop($parts);
        while (!empty($parts)) {
            $parentPath = '/' . implode('/', $parts);
            if (isset($accessList[$parentPath])) {
                return $accessList[$parentPath];
            }
            array_pop($parts);
        }
        return null;
    }

    /**
     * Get the special rights for a user
     *
     * @param int $user_id
     * @return array
     */
    public static function getSpecialRights(int $user_id): array
    {
        $systemRights = new systemRightsRepo();
        $systemRights->loadByWhere(['user_id' => $user_id]);

        $rights = [];
        foreach ($systemRights as $systemRight) {
            $rights[$systemRight->tool] = [
                'access' => $systemRight->access,
                'read' => $systemRight->read,
                'write' => $systemRight->write,
                'delete' => $systemRight->delete,
            ];
        }
        return $rights;
    }

    /**
     * Check if the user has the right to access a page based on the main path
     *
     * @param string $action
     * @return bool
     */
    public function checkRights(string $action = 'access'): bool
    {
        $path = $_SERVER['REQUEST_URI'];
        $path = explode('?', $path)[0];
        $path = rtrim($path, '/');

        return $this->processCheckRights($path, $action);
    }

    /**
     * Check if the user has the right to access a page based on a specific path
     *
     * @param string $path
     * @param string $action
     * @return bool
     */
    public function checkRightsForSpecificPath(string $path, string $action = 'access'): bool
    {
        if (!str_starts_with($path, '/')) {
            $path = '/' . $path;
        }
        $path = rtrim($path, '/');

        return $this->processCheckRights($path, $action);
    }

    /**
     * Recursively find the first parent path with level-rights set.
     */
    private function getFirstParentWithRights(string $path): ?array
    {
        // Remove trailing slash for consistency
        $path = rtrim($path, '/');

        // Find the immediate parent path by removing the last segment
        $parentPath = substr($path, 0, strrpos($path, '/'));

        // Check if the parent path exists and has level_rights defined
        if (isset($this->accessList[$parentPath]) && !empty($this->accessList[$parentPath]['level_rights'])) {
            return $this->accessList[$parentPath];
        }

        // If there's no parent path to check, return null
        if ($parentPath === '') {
            return null;
        }

        // Recursively check the next parent path up the chain
        return $this->getFirstParentWithRights($parentPath);
    }

    /**
     * Process the check rights
     *
     * @param string $path
     * @param string $action
     * @return bool
     */
    private function processCheckRights(string $path, string $action): bool
    {
        // Ensure the user is logged in
        if (!isset($_SESSION['user'])) {
            return false;
        }

        $rights = null;

        // Match the path in the access list with support for wildcards
        foreach ($this->accessList as $key => $value) {
            $pattern = '#^' . preg_replace('#\\\\\*#', '([^/]+)', preg_quote($key, '#')) . '$#';

            if (preg_match($pattern, $path)) {
                $path = $key;
                $rights = $value;
                break;
            }
        }

        // If no match is found, allow URLs or deny access
        if ($rights === null) {
            return str_starts_with($path, '/https://') || str_starts_with($path, '/http://');
        }

        // Validate level rights or special rights
        $userRight = $_SESSION['user']['right'];
        if (
            (
                empty($rights['level_rights'])
                || in_array($userRight, $rights['level_rights'])
                || $userRight == 100
            )
            || (
                isset($rights['special_rights'])
                && isset($_SESSION['userRights'][$rights['special_rights']])
                && $_SESSION['userRights'][$rights['special_rights']][$action]
            )
        ) {
            return true;
        }
        return false;
    }
}