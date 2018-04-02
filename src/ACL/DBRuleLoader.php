<?php
/*
This is part of Wedeto, the WEb DEvelopment TOolkit.
It is published under the MIT Open Source License.

Copyright 2017-2018, Egbert van der Wal

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

namespace Wedeto\Auth\ACL;

use Wedeto\Auth\Model\ACLRule;

/**
 * A RuleLoader that loads rules from the database using the Model\ACLRule class;
 */
class DBRuleLoader implements RuleLoaderInterface
{
    /**
     * Loads the rules for the specified entity from the database.
     */
    public function loadRules(string $entity_id)
    {
        $records = ACLRule::get(["entity_id" => $entity_id]);
        $rules = array();
        foreach ($records as $record)
        {
            $rule = new Rule($record->entity_id, $record->role_id, $record->action, $record->policy);
            $rule->setRecord($record);
            $rules[] = $rule;
        }

        return $rules;
    }
}
