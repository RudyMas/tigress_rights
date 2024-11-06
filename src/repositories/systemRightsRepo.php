<?php

namespace Repository;

use Tigress\Repository;

/**
 * Repository for system_rights table
 */
class systemRightsRepo extends Repository
{
    public function __construct()
    {
        $this->dbName = 'default';
        $this->table = 'system_rights';
        $this->model = 'systemRight';
        $this->autoload = true;
        parent::__construct();
    }
}