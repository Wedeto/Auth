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

namespace Wedeto\Auth\ACL
{

use PHPUnit\Framework\TestCase;

use Wedeto\DB\DB;
use Wedeto\DB\Schema\Column;
use Wedeto\DB\DAO;
use Wedeto\Util\DI\DI;

use TypeError;

/**
 * @covers Wedeto\Auth\ACL\ACLModel
 */
class ACLModelTest extends TestCase
{
    public function setUp()
    {
        $this->rl_mocker = $this->prophesize(RuleLoaderInterface::class);
        $this->rl = $this->rl_mocker->reveal();
        $this->acl = new ACL($this->rl);

        DI::startNewContext('test');
        DI::getInjector()->setInstance(ACL::class, $this->acl);

        $this->db_mock = $this->prophesize(DB::class);
        $this->db = $this->db_mock->reveal();
        DI::getInjector()->setInstance(DB::class, $this->db);
    }

    public function tearDown()
    {
        DI::destroyContext('test');
    }

    public function testACLModel()
    {
        $dao_mocker = $this->prophesize(DAO::class);
        $dao = $dao_mocker->reveal();

        $this->db_mock->getDAO(ACLModelMock::class)->willReturn($dao);
        $dao_mocker->getColumns()->willReturn([
            "id" => new Column\Serial("id"),
            "name" => new Column\Varchar("name")
        ]);
        $dao_mocker->getPrimaryKey()->willReturn([
            "id" => new Column\Serial("id")
        ]);

        $inst = new ACLModelMock;
        $this->assertEquals($this->acl, $inst->getACL());

        $entity = $inst->getACLEntity();
        $this->assertInstanceOf(Entity::class, $entity);

        $dao2_mocker = $this->prophesize(DAO::class);
        $dao2 = $dao2_mocker->reveal();
        $this->db_mock->getDAO(ACLModelMock2::class)->willReturn($dao2);
        $dao2_mocker->getColumns()->willReturn([
            "name" => new Column\Varchar("name"),
            "name2" => new Column\Varchar("name2"),
            "desc" => new Column\Varchar("desc")
        ]);
        $dao2_mocker->getPrimaryKey()->willReturn([
            "name" => new Column\Varchar("name"),
            "name2" => new Column\Varchar("name2")
        ]);

        $inst2 = new ACLModelMock2("foo", "bar");
        $this->assertEquals($this->acl, $inst2->getACL());

        $entity = $inst2->getACLEntity();
        $this->assertInstanceOf(Entity::class, $entity);

        $inst3 = new ACLModelMock2(null, null);
        $this->assertNull($inst3->getACLEntity());
    }

    public function testGetACLClass()
    {
        $this->assertEquals("Wedeto_ACLModelMock", ACLModelMock::getACLClass());
        $this->assertEquals("Wedeto_ACLModelMock2", ACLModelMock2::getACLClass());
        $this->assertEquals("ACLModelMock3", \ACLModelMock3::getACLClass());
    }

    public function testIsAllowedWithoutEntityUsesDefaults()
    {
        $inst = new ACLModelMock2(null, null);

        $this->acl->setDefaultPolicy(Rule::ALLOW);
        $this->assertEquals(Rule::ALLOW, $inst->isAllowed(Rule::READ));
        $this->acl->setDefaultPolicy(Rule::DENY);
        $this->assertEquals(Rule::DENY, $inst->isAllowed(Rule::READ));
    }

    public function testIsAllowedWithEntityIDWithNoRules()
    {
        $dao_mocker = $this->prophesize(DAO::class);
        $dao = $dao_mocker->reveal();

        $this->db_mock->getDAO(ACLModelMock::class)->willReturn($dao);
        $dao_mocker->getColumns()->willReturn([
            "id" => new Column\Serial("id"),
            "name" => new Column\Varchar("name")
        ]);
        $dao_mocker->getPrimaryKey()->willReturn([
            "id" => new Column\Serial("id")
        ]);

        $inst = new ACLModelMock();
        
        // There are no rules yet, so the default should be returned
        $this->acl->setDefaultPolicy(Rule::ALLOW);
        $this->assertTrue($inst->isAllowed(Rule::READ));

        // Change default and try again
        $this->acl->setDefaultPolicy(Rule::DENY);
        $this->assertFalse($inst->isAllowed(Rule::READ));
    }

    public function testIsAllowedWithEntityIDAndRules()
    {
        $dao_mocker = $this->prophesize(DAO::class);
        $dao = $dao_mocker->reveal();

        $this->db_mock->getDAO(ACLModelMock::class)->willReturn($dao);
        $dao_mocker->getColumns()->willReturn([
            "id" => new Column\Serial("id"),
            "name" => new Column\Varchar("name")
        ]);
        $dao_mocker->getPrimaryKey()->willReturn([
            "id" => new Column\Serial("id")
        ]);

        $inst = new ACLModelMock();
        $this->rl_mocker->loadRules($inst->generateID())->willReturn([
            new Rule($this->acl, $inst->generateID(), Role::getRootName(), Rule::READ, Rule::ALLOW)
        ]);
        
        // Rules should be present
        $this->assertTrue($inst->isAllowed(Rule::READ));

        // A new instance should share the rules
        $inst2 = new ACLModelMock();
        $this->assertTrue($inst2->isAllowed(Rule::READ));
    }
}

class ACLModelMock extends ACLModel
{
    public function __construct()
    {
        $this->id = 1337;
        $this->init();
    }
}

class ACLModelMock2 extends ACLModel
{
    public function __construct($n1, $n2)
    {
        if ($n1)
            $this->name = $n1;
        if ($n2)
            $this->name2 = $n2;
        $this->init();
    }
}
}

namespace
{
class ACLModelMock3 extends Wedeto\Auth\ACL\ACLModel
{}
}
