<?php

namespace Tigress;

use Repository\systemRightsRepo;

/**
 * Class Rights (PHP version 8.3)
 *
 * @author       Rudy Mas <rudy.mas@rudymas.be>
 * @copyright    2024, Rudy Mas (http://rudymas.be/)
 * @license      https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version      1.5.2
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
        return '1.5.2';
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
        $requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        return $this->processCheckRights($path, $action, $requestMethod);
    }

    /**
     * Check if the user has the right to access a page based on a specific path
     *
     * @param string $path
     * @param string $action
     * @param string $requestMethod
     * @return bool
     */
    public function checkRightsForSpecificPath(string $path, string $action = 'access', string $requestMethod = 'GET'): bool
    {
        if (!str_starts_with($path, '/')) {
            $path = '/' . $path;
        }
        $path = rtrim($path, '/');

        return $this->processCheckRights($path, $action, $requestMethod);
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
     * Set the access list
     *
     * @return void
     */
    public function setRights(): void
    {
        // First, build the access list for paths that explicitly have rights
        foreach (ROUTES->routes as $route) {
            $path = preg_replace('/{[^}]+}/', '*', $route->path);
            $requestMethod = $route->request ?? 'GET';

            if (!isset($this->accessList[$path][$requestMethod])) {
                $this->accessList[$path][$requestMethod] = [];
            }

            $this->accessList[$path][$requestMethod]['level_rights'] = $route->level_rights ?? [];

            if (isset($route->special_rights)) {
                $this->accessList[$path][$requestMethod]['special_rights'] = $route->special_rights;
            }

            if (isset($route->special_rights_default)) {
                $this->accessList[$path][$requestMethod]['special_rights_default'] = $route->special_rights_default;
            }
        }

        // Now inherit rights from the first parent that has them defined
        foreach (ROUTES->routes as $route) {
            $path = preg_replace('/{[^}]+}/', '*', $route->path);
            $requestMethod = $route->request ?? 'GET';

            if (empty($this->accessList[$path][$requestMethod]['level_rights']) &&
                empty($this->accessList[$path][$requestMethod]['special_rights']) &&
                empty($this->accessList[$path][$requestMethod]['special_rights_default'])
            ) {
                $parentRights = $this->getFirstParentWithRights($path, $requestMethod);
                if ($parentRights) {
                    $this->accessList[$path][$requestMethod] = array_merge($this->accessList[$path][$requestMethod], $parentRights);
                }
            }
        }
    }

    /**
     * Get the first parent path with rights
     *
     * @param string $path
     * @param string $requestMethod
     * @return array|null
     */
    private function getFirstParentWithRights(string $path, string $requestMethod): ?array
    {
        // Remove trailing slash for consistency
        $path = rtrim($path, '/');

        // Find the immediate parent path by removing the last segment
        $parentPath = substr($path, 0, strrpos($path, '/'));

        if (isset($this->accessList[$parentPath][$requestMethod]) &&
            !empty($this->accessList[$parentPath][$requestMethod]['level_rights'])) {
            return $this->accessList[$parentPath][$requestMethod];
        }

        // If there's no parent path to check, return null
        if ($parentPath === '') {
            return null;
        }

        return $this->getFirstParentWithRights($parentPath, $requestMethod);
    }

    /**
     * Process the check rights
     *
     * @param string $path
     * @param string $action
     * @param string $requestMethod
     * @return bool
     */
    private function processCheckRights(string $path, string $action, string $requestMethod): bool
    {
        // Ensure the user is logged in
        if (!isset($_SESSION['user'])) {
            return false;
        }

        $rights = null;

        foreach ($this->accessList as $key => $methods) {
            $pattern = '#^' . preg_replace('#\\\\\*#', '([^/]+)', preg_quote($key, '#')) . '$#';

            if (preg_match($pattern, $path) && isset($methods[$requestMethod])) {
                $path = $key;
                $rights = $methods[$requestMethod];
                break;
            }
        }

        // If no match is found, allow URLs or deny access
        if ($rights === null) {
            return str_starts_with($path, '/https://') || str_starts_with($path, '/http://');
        }

        // Validate level rights or special rights
        $userRight = $_SESSION['user']['access_level'];
        return (
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
        );
    }

    /**
     * Get the access list
     *
     * @return array
     */
    public function getAccessList(): array
    {
        return $this->accessList;
    }
}