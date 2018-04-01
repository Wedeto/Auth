<?php
/*
This is part of Wedeto, the WEb DEvelopment TOolkit.
It is published under the MIT Open Source License.

Copyright 2018, Egbert van der Wal

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

use PHPUnit\Framework\TestCase;

use Wedeto\Auth\ACL\Exception as ACLException;
use Wedeto\DB\DB;
use Wedeto\DB\DAO;
use Wedeto\Util\DI\DI;

/**
 * @covers Wedeto\Auth\ACL\ACL
 */
class ACLTest extends TestCase
{
    public function setUp()
    {
        $this->rl_mocker = $this->prophesize(RuleLoaderInterface::class);
        $this->rl = $this->rl_mocker->reveal();

        DI::startNewContext('test');
    }

    public function tearDown()
    {
        DI::destroyContext('test');
    }

    public function testConstructionWithRuleLoader()
    {
        $acl = new ACL($this->rl);
        $this->assertSame($this->rl, $acl->getRuleLoader());

        $another = $this->prophesize(RuleLoaderInterface::class);
        $another_rl = $another->reveal();
        $this->assertSame($acl, $acl->setRuleLoader($another_rl));
        $this->assertSame($another_rl, $acl->getRuleLoader());
    }

    public function testRegisterClassesAndGetByACLID()
    {
        $acl = new ACL($this->rl);
        $db_mock = $this->prophesize(DB::class);
        $db = $db_mock->reveal();
        

        $dao_mock = $this->prophesize(DAO::class);
        $dao_mock->get(['bar'])->willReturn(new ACLTestACLModelMock($acl));
        $dao = $dao_mock->reveal();

        $db_mock = $this->prophesize(DB::class);
        $db_mock->getDAO(ACLTestACLModelMock::class)->willReturn($dao);
        $db = $db_mock->reveal();

        DI::getInjector()->setInstance(DB::class, $db);
        $acl->registerClass(ACLTestACLModelMock::class, 'foo');
        $entity = $acl->loadByACLID('foo#bar');

        $this->assertInstanceOf(ACLTestAclModelMock::class, $entity);

    }
}

class ACLTestACLModelMock extends Hierarchy
{
    public static $test_dao = null;
}
