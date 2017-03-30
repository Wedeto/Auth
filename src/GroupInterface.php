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

namespace Wedeto\Auth;

interface GroupInterface
{
    /**
     * @return string A name of this group to be displayed to the user
     */
    public function getDisplayName();

    /**
     * Initialize the group using the Group ID. This should be the same ID
     * that is returned by GroupInterface::getGroupID.
     *
     * @param string $group_id The Group ID to load
     * @return Wedeto\Auth\GroupInteface Provides fluent interface
     * @throws Wedeto\Auth\NotFoundException When the group does not exist
     */
    public function obtainByGroupID(string $group_id);

    /** 
     * @return string A token identifying the group uniquely and statically,
     *                such as a database ID.
     *
     * This should not be anything changeable, ever, so group names should be
     * avoided. ACL will use this to identify roles, and will prefix the ID
     * with 'G' to indicate it being a group to avoid duplicates.
     */
    public function getGroupId();
    
    /**
     * @param Wedeto\Auth\UserInterface The user to check
     * @return bool True if the specified user is a member of this group, false
     *              if not.
     */
    public function isMember(UserInterface $user);
}

