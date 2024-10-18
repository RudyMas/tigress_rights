<?php

namespace Tigress;

use Repository\system_rightsRepo;

/**
 * Class Rights (PHP version 8.3)
 *
 * @author       Rudy Mas <rudy.mas@rudymas.be>
 * @copyright    2024, Rudy Mas (http://rudymas.be/)
 * @license      https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version      1.0.3
 * @lastmodified 2024-09-18
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
        return '1.0.3';
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
            $path = $route->path;

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

        // Now inherit rights from parent paths for routes that don't have them defined
        foreach (ROUTES->routes as $route) {
            $path = $route->path;

            // Only inherit rights if level-rights, special-rights, and special-rights-default are empty
            if (empty($this->accessList[$path]['level_rights']) && empty($this->accessList[$path]['special_rights']) && empty($this->accessList[$path]['special_rights_default'])) {
                $parentRights = $this->getParentRights($path, $this->accessList);
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
        $systemRights = new system_rightsRepo();
        $systemRights->loadByWhere(['user_id' => $user_id]);

        $rights = [];
        foreach ($systemRights as $systemRight) {
            $rights[$systemRight->tool] = [
                'toegang' => $systemRight->toegang,
                'lees' => $systemRight->lees,
                'schrijf' => $systemRight->schrijf,
                'verwijder' => $systemRight->verwijder,
            ];
        }
        return $rights;
    }
}