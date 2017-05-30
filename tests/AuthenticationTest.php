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

use Wedeto\IO\IOException;
use Wedeto\HTTP\Session;

/**
 * @covers Wedeto\Auth\Authentication
 */
class AuthenticationTest extends TestCase
{
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

    public function testLogin()
    {
        $password = 'foobar';
        $config = ['algorithm' => PASSWORD_DEFAULT, 'cost' => 5, 'salt' => 'foo'];
        $auth = new Authentication($config);

        $hash = $auth->hash($password);
        $session = new MockSession();
        
        $auth->login('user', $password, $session);
    }
}

class MockSession extends Session
{
    public function __construct()
    {
        $this->active = true;
    }
}

class MockUser implements UserInterface
{
    public function obtainFromLogin(string $username, string $password);
    public function obtainFromSession(Session $session);
    public function obtainByUserID(string $user_id);
    public function isLoggedIn();
    public function getGroups();
    public function getUserID();
    public function getDisplayName();
    public function getEmailAddress();
}
