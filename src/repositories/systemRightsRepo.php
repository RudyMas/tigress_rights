<?php

namespace Repository;

use Tigress\Core;
use Tigress\Repository;

/**
 * Repository for system_rights table
 */
class systemRightsRepo extends Repository
{
    private array $rechtenMatrix = [];

    public function __construct()
    {
        $this->dbName = 'default';
        $this->table = 'system_rights';
        $this->model = 'systemRight';
        $this->primaryKey = ['user_id', 'tool'];
        $this->autoload = true;
        parent::__construct();
    }

    public function updateRechtenGebruiker(string $jsonMenuFile, int $id, int $recht): void
    {
        $rechtenMatrix = $this->createRechtenMatrix($jsonMenuFile, $id, $recht);

        $sql = "DELETE FROM system_rights
                WHERE user_id = :id";
        $keyBindings = [
            ':id' => $id
        ];
        $this->deleteByQuery($sql, $keyBindings);
        if (isset($rechtenMatrix['rechten'])) {
            foreach ($rechtenMatrix['rechten'] as $tool => $data) {
                $access = $data['toegang'] ?? 0;
                $read = $data['lees'] ?? 0;
                $write = $data['schrijf'] ?? 0;
                $delete = $data['verwijder'] ?? 0;

                $this->new();
                $user = $this->current();
                $user->user_id = $rechtenMatrix['id'];
                $user->tool = $tool;
                $user->access = $access;
                $user->read = $read;
                $user->write = $write;
                $user->delete = $delete;
            }
            $this->saveAll();
        }
    }

    /**
     * Create the security matrix
     *
     * @param string $jsonMenuFile
     * @return array
     */
    public function createSecurityMatrix(string $jsonMenuFile): array
    {
        $data = json_decode(file_get_contents(SYSTEM_ROOT . '/src/menus/' . $jsonMenuFile), true);
        $rights = RIGHTS->getAccessList();

        $security = [];
        foreach ($data as $key => $value) {
            foreach ($value as $keySub => $valueSub) {
                if (!isset($rights[$valueSub['url']]['GET'])) continue;
                $security[$key][$keySub] = $rights[$valueSub['url']]['GET'];
            }
        }
        return $security;
    }

    /**
     * Get the rights by user id
     *
     * @param int $id
     * @return array
     */
    public function getRightsByUserId(int $id): array
    {
        $this->loadByWhere(['user_id' => $id]);

        $rights = [];
        foreach ($this as $systemRight) {
            $rights[$systemRight->tool] = $systemRight->getProperties();
        }
        return $rights;
    }

    /**
     * Create the rights matrix
     *
     * @param string $jsonMenuFile
     * @param int $id
     * @param int $recht
     * @return array
     */
    private function createRechtenMatrix(string $jsonMenuFile, int $id, int $recht): array
    {
        $security = $this->createSecurityMatrix($jsonMenuFile);

        $rechtenMatrix = [];
        $matrix = [];
        foreach ($security as $value) {
            if (!strpos(json_encode($value), 'special_rights_default')) continue;
            foreach ($value as $valueSub) {
                if (!isset($valueSub['special_rights_default'])) continue;
                if (in_array($recht, $valueSub['special_rights_default'])) {
                    $matrix[$valueSub['special_rights']] = [
                        'toegang' => 1,
                        'lees' => 1,
                        'schrijf' => 1,
                        'verwijder' => 1,
                    ];
                }
            }
        }
        $rechtenMatrix['id'] = $id;
        $rechtenMatrix['rechten'] = $matrix;
        return $rechtenMatrix;
    }
}