<?php

namespace Repository;

use Tigress\Repository;

/**
 * Repository for the gunaRechten table
 */
class SystemLockPagesRepo extends Repository
{
    public function __construct()
    {
        $this->dbName = 'default';
        $this->table = 'system_lock_pages';
        $this->primaryKey = ['resource', 'resource_id'];
        $this->model = 'DefaultModel';
        $this->autoload = true;
        parent::__construct();
    }
}