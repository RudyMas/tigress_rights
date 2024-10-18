<?php

namespace Repository;

use Tigress\Repository;

/**
 * Repository for users table
 */
class system_rightsRepo extends Repository
{
    public function __construct()
    {
        $this->dbName = 'default';
        $this->table = 'system_rights';
        $this->model = 'system_right';
        $this->autoload = true;
        parent::__construct();
    }
}