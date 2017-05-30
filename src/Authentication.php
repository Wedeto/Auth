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

use Wedeto\Util\Dictionary;
use Wedeto\HTTP\Session;
use Wedeto\Util\Type;

/**
 * Handle authentication - log in users, verify passwords and load users
 * and groups.
 */
class Authentication
{
    /** The configuration for authentication */
    protected $config;

    /* The class representing users */
    protected $user_class;

    /** The group class representing groups */
    protected $group_class;

    /** The currently logged in user */
    protected $user;

    /**
     * Construct the authentication object using a configuration.
     * @param array $config An array or array-like object to get configuration from
     */
    public function __construct($config)
    {
        $config = new Dictionary($config);

        if ($config->has('auth', Type::ARRAY))
            $this->config = $config->getSection('auth');
        else
            $this->config = $config;
    }
    
    /**
     * Set the UserInterface class that represents users.
     * @param string $classname The class to use for users. This should implement
     *                          Wedeto\Auth\UserInterface.
     * @return Wedeto\Auth\Authentication Provides fluent interface
     */
    public function setUserClass(string $classname)
    {
        if (!class_exists($classname) || !is_subclass_of($classname, UserInterface::class))
            throw new DomainException("Invalid user class: $class");
        $this->user_class = $classname;
        return $this;
    }

    /**
     * Set the GroupInterface class that represents groups.
     * @param string $classname the class to use for gruops. This should implement
     *                          Wedeto\Auth\GroupInterface.
     * @return Wedeto\Auth\Authentication PRovides fluent interface
     */
    public function setGroupClass(string $classname)
    {
        if (!class_exists($classname) || !is_subclass_of($class, GroupInterface::class))
            throw new DomainException("Invalid group class: $class");
        $this->group_class = $classname;
        return $this;
    }

    /**
     * Get the UserInterface class that represents users.
     * Defauls to Wedeto\Auth\Model\User but can be overridden in the config to
     * use alternative authentication - for example integration with different
     * software.
     * @return string The class implementing Wedeto\Auth\UserInterface
     */
    protected function getUserClass()
    {
        if ($this->user_class === null)
        {
            $class = $this->config->dget('user_class', 'Wedeto\\Auth\\Model\\User');
            $class = str_replace('.', '\\', $class);

            if (!class_exists($class) || !is_subclass_of($class, UserInterface::class))
                throw new DomainException("Invalid user class: $class");
            $this->user_class = $class;
        }
        
        return $this->user_class;
    }

    /**
     * Get the UserInterface class that represents users.
     * Defauls to Wedeto\Auth\Model\User but can be overridden in the config to
     * use alternative authentication - for example integration with different
     * software.
     * @return string The class implementing Wedeto\Auth\UserInterface
     */
    protected function getGroupClass()
    {
        if ($this->group_class === null)
        {
            $class = $this->config->dget('group_class', 'Wedeto\\Auth\\Model\\Group');
            $class = str_replace('.', '\\', $class);

            if (!class_exists($class) || !is_subclass_of($class, GroupInterface::class))
                throw new DomainException("Invalid group class: $class");
            $this->group_class = $class;
        }
        
        return $this->group_class;
    }

    /**
     * Obtain the current user from the active session
     * @param Wedeto\HTTP\Session $session The session object
     * @return Wedeto\Auth\UserInteface The current user. Can be anonymous if
     *                                noone is logged in.
     */
    public function getUserFromSession(Session $session)
    {
        $cl = $this->getUserClass();
        $this->user = new $cl;
        $this->user->obtainFromSession($session);
        return $this->user;
    }

    /**
     * Obtain a user by its user ID. 
     * @param string $userID The User ID to load
     * @return Wedeto\Auth\UserInterface The user
     * @throws Wedeto\Auth\NotFoundException When the user does not exist
     */
    public function getUser(string $userid)
    {
        $cl = $this->getUserClass();
        $user = new $cl;
        return $user->obtainByUserID($userid);
    }

    /**
     * Obtain a group by its group ID.
     * @param string $groupid The group ID to load
     * @return Wedeto\Auth\GroupInterface The loaded group
     * @throws Wedeto\Auth\NotFoundException When the group does not exist
     */
    public function getGroup(string $groupid)
    {
        $cl = $this->getGroupClass();
        $group = new $cl;
        return $group->obtainByGroupID($groupid);
    }

    /**
     * @return Wedeto\User\UserInterface The logged in user
     */
    public function currentUser()
    {
        return $this->user;
    }
    
    /**
     * Check if the provided details contain a valid login.
     * @param string $username The user to log in
     * @param string $password The password to verify
     * @param Wedeto\HTTP\Session $session The session to log into
     * @throws Wedeto\Auth\AuthenticationError When logging in fails
     * @return Wedeto\Auth\UserInterface The logged in user
     */
    public function login(string $username, string $password, Session $session)
    {
        if ($session->has('authentication', 'user_id'))
        {
            throw new AuthenticationError(
                "Already logged in",
                AuthenticationError::DUPLICATE_SESSION
            );
        }

        $cl = $this->getUserClass();
        $this->user = new $cl;
        $this->user->obtainFromLogin($username, $password);
        $session->set('authentication', 'user_id', $this->user->getUserID());
        return $this->user;
    }

    /**
     * Create a hash of the password
     * @param string $password The password to hash
     * @return string The hashed password
     */
    public function hash(string $password)
    {
        $algorithm = $this->config->dget('algorithm', PASSWORD_DEFAULT);
        $options['cost'] = $this->config->dget('cost', 10);

        return password_hash($password, $algorithm, $options);
    }

    /**
     * Check if the password matches the provided hash. The password
     * should come from user input, the hash from persistent storage.
     * @param string $password The password to verify
     * @param string $hash The hash of the correct password
     * @return bool True if the password matches the hash, false if it does
     * not.
     */
    public function verify(string $password, string $hash)
    {
        if (substr($hash, 0, 1) !== "$")
        {
            $salt = $this->config->dget('salt', '');
            $pw_hash = hash('sha256', $password . $salt);
            return $pw_hash === $hash;
        }

        return password_verify($password, $hash);
    }

    /**
     * Check if the password needs a rehash
     * @param string $hash The hash to check
     * @return bool True if the password needs to be rehashed, false if not
     */
    public function needsRehash(string $hash)
    {
        if (substr($hash, 0, 1) !== "$")
            return true;

        $algorithm = $this->config->dget('algorithm', PASSWORD_DEFAULT);
        $options['cost'] = $this->config->dget('cost', 10);
        return password_needs_rehash($hash, $algorithm, $options);
    }
}
