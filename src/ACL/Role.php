<?php
/*
This is part of Wedeto, the WEb DEvelopment TOolkit.
It is published under the MIT Open Source License.

Copyright 2017, Egbert van der Wal

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

namespace Wedeto\ACL;

/**
 * The Role is a user or group of users to which Rules apply.
 * Each Role has one or more parents, and at the top of the
 * hierarchy is the class 'Everyone' that is the ancestor of all Roles.
 */
class Role extends Hierarchy
{
    protected static $root = "EVERYONE";

    /**
     * Create the Role object providing its ID and a list of parents
     */
    public function __construct($role_id, $parents = array())
    {
        if (!is_scalar($role_id))
            throw new Exception("Role-ID must be scalar");
        if (isset(self::$database[$role_id]))
            throw new Exception("Duplicate role $role_id");

        $this->id = $role_id;
        $this->setParents($parents);
        self::$database[get_class($this)][$role_id] = $this;
    }

    /**
     * Provide access to properties
     *
     * @param $field string The name of the property to get
     * @return The value of the property
     * @throws Wedeto\ACL\Exception When the field does not exist
     */
    public function __get($field)
    {
        if (!property_exists($this, $field))
            throw new Exception("Invalid field for Role: $field");

        return $this->field;
    }
}
