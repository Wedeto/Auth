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

use Wedeto\HTTP\Session;

/**
 * The interface user providers should implement. Any object should be 
 * instantiatable by either obtainFromLogin, obtainFromSession or obtainFromUserId.
 * Any object not instantiated by any of these represents the anonymous user, and
 * should return UserInterface::ANONYMOUS_USER as getUserId
 */
interface UserInterface
{
    const ANONYMOUS_USER = "_WEDETO_ANONYMOUS_";

    /**
     * Attempt to log the user in given the provided username and password.
     *
     * @param string $username The username provided
     * @param string $password The password entered
     * @throws Wedeto\Auth\AuthenticationError When login failed
     */
    public function obtainFromLogin(string $username, string $password);

    /**
     * Get a user object from the session object provided.
     *
     * @param Wedeto\HTTP\Session $session The session object where to get session variables from
     * @return bool True when logged in, false if not
     */
    public function obtainFromSession(Session $session);

    /**
     * Return a User object using the user ID. This should be the same user ID returned by
     * getUserID.
     *
     * @param string $user_id The User ID of the user to load
     * @return Wedeto\UserInterface Provides fluent interface
     * @throws Wedeto\Auth\NotFoundException When the user does not exist
     * @see UserInterface::getUserID
     */
    public function obtainByUserID(string $user_id);

    /**
     * @return bool True if the user is logged in, false if the user is not logged in.
     *              This should only ever be true for the User initialized by
     *              'login' or 'obtainFromSession', and not from 'obtainByUserID'.
     */
    public function isLoggedIn();

    /**
     * @return array A list of Wedeto\Auth\GroupInterface objects that this user is in
     */
    public function getGroups();

    /** 
     * @return string A token identifying the user uniquely and statically,
     *                such as a database ID.
     *
     * This should not be anything changeable, ever, so user names and
     * e-mail addresses should be avoided. ACL will use this to identify roles,
     * and will prefix the ID with 'U' to indicate it being an user to avoid
     * duplicates.
     */
    public function getUserID();

    /**
     * @return string A name to be displayed to the user
     */
    public function getDisplayName();

    /**
     * @return string The e-mail address of the current user, can be used to contact the user
     */
    public function getEmailAddress();
}
