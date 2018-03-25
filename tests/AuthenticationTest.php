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

use PHPUnit\Framework\TestCase;

use Wedeto\Util\Dictionary;
use Wedeto\Util\Validation\Type;
use Wedeto\IO\IOException;
use Wedeto\HTTP\Session;
use Wedeto\HTTP\URL;

/**
 * @covers Wedeto\Auth\Authentication
 */
class AuthenticationTest extends TestCase
{
    public function setUp()
    {
        // Reset call logs
        MockUser::getCalled();
        MockGroup::getCalled();
    }

    public function testPasswordHashing()
    {
        $config = ['algorithm' => PASSWORD_DEFAULT, 'cost' => 5, 'salt' => 'foo'];
        
        $auth = new Authentication($config);
        $password = 'foobar';
        $hash = $auth->hash($password);
        $hash2 = $auth->hash($password);

        $this->assertNotEquals($hash, $hash2, "Equal hashes generated");
        $this->assertTrue($auth->verify($password, $hash));
        $this->assertTrue($auth->verify($password, $hash2));
        $this->assertFalse($auth->verify($password, $hash . $hash2));
        $this->assertFalse($auth->needsRehash($hash));
        $this->assertFalse($auth->needsRehash($hash2));

        $shahash = hash('sha256', $password . $config['salt']);
        $this->assertTrue($auth->verify($password, $shahash), "SHA Hash does not work");
        $this->assertTrue($auth->needsRehash($shahash));
    }

    public function testPasswordHashingRoundsDiffer()
    {
        $password = 'foobar';
        $last_elapsed = 0;

        for ($cost = 4; $cost < 8; ++$cost)
        {
            $config = ['algorithm' => PASSWORD_DEFAULT, 'cost' => $cost, 'salt' => 'foo'];
            $auth = new Authentication($config);

            $start = microtime(true);
            $hash = $auth->hash($password);
            $this->assertTrue($auth->verify($password, $hash));
            $this->assertFalse($auth->verify($password . 'foo', $hash));
            $end = microtime(true);
            $elapsed = $end - $start;

            $this->assertGreaterThan($last_elapsed, $elapsed, "Cost $cost does not take longer than previous cost");
        }
    }

    public function testSetInvalidUserClass()
    {
        $auth = new Authentication([]);

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage("Invalid user class: stdClass");
        $this->assertSame($auth, $auth->setUserClass(\stdClass::class));
    }

    public function testSetInvalidGroupClass()
    {
        $auth = new Authentication([]);

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage("Invalid group class: stdClass");
        $auth->setGroupClass(\stdClass::class);
    }

    public function testLogin()
    {
        $password = 'foobar';
        $config = ['auth' => ['algorithm' => PASSWORD_DEFAULT, 'cost' => 5, 'salt' => 'foo']];
        $auth = new Authentication($config);

        $hash = $auth->hash($password);
        $url = new URL("http://localhost/");
        $conf = new Dictionary;
        $session = new Session($url, $conf, $conf);
        $session->start();
        
        $this->assertSame($auth, $auth->setUserClass(MockUser::class));
        $user = $auth->login('user', $password, $session);

        $this->assertInstanceOf(MockUser::class, $user);
        $called = MockUser::getCalled();

        $this->assertEquals(2, count($called));

        $call = $called[0];
        $this->assertEquals('obtainFromLogin', $call['method']);
        $this->assertSame($user, $call['this']);
        $this->assertEquals('user', $call['params'][0]);
        $this->assertEquals($password, $call['params'][1]);

        $call = $called[1];
        $this->assertEquals('getUserID', $call['method']);
        $this->assertSame($user, $call['this']);
        $this->assertEmpty($call['params']);

        $this->assertTrue($session->has('authentication', 'user_id', Type::STRING));
        $this->assertEquals($user->getUserID(), $session->get('authentication', 'user_id'));
        $this->assertSame($user, $auth->currentUser());

        // Detect duplicate logins
        $thrown = false;
        try
        {
            $user = $auth->login('user', $password, $session);
        }
        catch (AuthenticationError $e)
        {
            $this->assertEquals('Already logged in', $e->getMessage());
            $this->assertEquals(AuthenticationError::DUPLICATE_SESSION, $e->getCode());
            $thrown = true;
        }
        $this->assertTrue($thrown, "Duplicate login should throw exception");

        MockUser::setLoginExceptionClass(AuthenticationError::class);
        $session->clear();

        $thrown = false;
        try
        {
            $user = $auth->login('user', $password, $session);
        }
        catch (AuthenticationError $e)
        {
            $this->assertEquals('Fail', $e->getMessage());
            $thrown = true;
        }
        $this->assertTrue($thrown, "Login should fail");

        $thrown = false;
        MockUser::setLoginExceptionClass(\RuntimeException::class);
        $session->clear();

        try
        {
            $user = $auth->login('user', $password, $session);
        }
        catch (AuthenticationError $e)
        {
            $this->assertEquals('Login failed', $e->getMessage());
            $this->assertEquals(\RuntimeException::class, get_class($e->getPrevious()));
            $thrown = true;
        }
        $this->assertTrue($thrown, "Other exceptions should be wrapped in AuthenticationError");
    }

    public function testGetUser()
    {
        $auth = new Authentication([]);
        $this->assertSame($auth, $auth->setUserClass(MockUser::class));
        
        $user = $auth->getUser('foo');
        $called = MockUser::getCalled();
        $this->assertEquals(1, count($called));
        $call = $called[0];
        $this->assertEquals('obtainByUserID', $call['method']);
        $this->assertEquals(1, count($call['params']));
        $this->assertEquals('foo', $call['params'][0]);
    }

    public function testGetUserFromSession()
    {
        $url = new URL("http://localhost/");
        $conf = new Dictionary;
        $session = new Session($url, $conf, $conf);
        $session->start();
        $session->clear();

        $auth = new Authentication([]);
        $this->assertSame($auth, $auth->setUserClass(MockUser::class)); 
        $user = $auth->getUserFromSession($session);
        $this->assertInstanceOf(MockUser::class, $user);
        $this->assertEquals('mock', $user->getUserID());

        $session->set('authentication', 'user_id', 'foo');
        $user = $auth->getUserFromSession($session);
        $this->assertInstanceOf(MockUser::class, $user);
        $this->assertEquals('foo', $user->getUserID());
    }

    public function testGetGroup()
    {
        $auth = new Authentication([]);

        $this->assertSame($auth, $auth->setGroupClass(MockGroup::class));

        $group = $auth->getGroup('mock');
        $called = MockGroup::getCalled();

        $this->assertEquals(1, count($called));
        $call = $called[0];
        $this->assertEquals('obtainByGroupID', $call['method']);
        $this->assertEquals(1, count($call['params']));
        $this->assertEquals('mock', $call['params'][0]);

        $this->assertInstanceOf(MockGroup::class, $group);
    }
}

class MockUser implements UserInterface
{
    protected static $called = [];
    protected static $exc_class = null;

    protected $user_id = 'mock';

    public static function getCalled()
    {
        $cl = self::$called;
        self::$called = [];
        return $cl;
    }

    public static function setLoginExceptionClass(string $class)
    {
        self::$exc_class = $class;
    }

    public function obtainFromLogin(string $username, string $password)
    {
        if (self::$exc_class)
            throw new self::$exc_class("Fail");

        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
    }

    public function obtainFromSession(Session $session)
    {
        $this->user_id = $session->dget('authentication', 'user_id', 'mock');
        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
    }

    public function obtainByUserID(string $user_id)
    {
        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
    }

    public function isLoggedIn()
    {
        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
    }

    public function getGroups()
    {
        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
    }

    public function getUserID()
    {
        self::$called[] = ['method' => 'getUserID', 'this' => $this, 'params' => []];
        return $this->user_id;
    }

    public function getDisplayName()
    {
        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
    }

    public function getEmailAddress()
    {
        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
    }
}

class MockGroup implements GroupInterface
{
    protected static $called = [];

    public static function getCalled()
    {
        $cl = self::$called;
        self::$called = [];
        return $cl;
    }

    public function getDisplayName()
    {
        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
    }

    public function obtainByGroupID(string $group_id)
    {
        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
        return $this;
    }

    public function getGroupId()
    {
        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
        return 'mock';
    }

    public function isMember(UserInterface $user)
    {
        self::$called[] = ['method' => __FUNCTION__, 'this' => $this, 'params' => func_get_args()];
    }
}
