<?php

use Wedeto\DB\Query\Builder AS QB;
use Wedeto\DB\Schema\Table;
use Wedeto\DB\Schema\Column;
use Wedeto\DB\Schema\Index;

$drv = $db->getDriver();
$prefix = $drv->getTablePrefix();
$table = $drv->identQuote($prefix . "acl_rule");

$db->exec("DROP TABLE " . $table);
