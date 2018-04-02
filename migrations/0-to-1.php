<?php

use Wedeto\DB\Query\Builder AS QB;
use Wedeto\DB\Schema\Table;
use Wedeto\DB\Schema\Column;
use Wedeto\DB\Schema\Index;

$table = new Table(
    "acl_rule",
    new Column\Serial('id'),
    new Column\Varchar('entity_id', 128),
    new Column\Varchar('role_id', 128),
    new Column\Smallint('action'),
    new Column\Smallint('policy'),
    new Column\Datetime('last_modified'),
    new Index(Index::PRIMARY, 'id'),
    new Index(Index::UNIQUE, 'entity', 'role', 'action')
);

$db->getDriver()->createTable($table);
