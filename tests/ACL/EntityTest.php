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

use PHPUnit\Framework\TestCase;

use Wedeto\Auth\ACL\Exception as ACLException;
use Wedeto\DB\DAO;

/**
 * @covers Wedeto\Auth\ACL\Entity
 * @covers Wedeto\Auth\ACL\Hierarchy
 * @covers Wedeto\Auth\ACL\ACL
 */
class EntityTest extends TestCase
{
    public function setUp()
    {
        $rl = $this->prophesize(RuleLoaderInterface::class);
        $this->acl = new ACL($rl->reveal());
    }

    public function testConstructionWithIDWorks()
    {
        $entity = new Entity($this->acl, 'foo');
        $this->assertEquals('foo', $entity->getID());

        $entity = new Entity($this->acl, 'bar');
        $this->assertEquals('bar', $entity->getID());
    }

    public function testConstructWithNonScalar()
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage("must be of the type string, array given");
        $entity = new Entity($this->acl, ['foo']);
    }

    public function testDuplicateConstructionThrowsException()
    {
        $foo1 = new Entity($this->acl, 'foo');

        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Duplicate entity: foo");
        $foo2 = new Entity($this->acl, 'foo');
    }

    public function testGenerateID()
    {
        $mock = new MockModel(123);
        $id = $mock->generateID($mock);
        $sum = substr(sha1('123'), 0, 10);
        $this->assertEquals('Wedeto_MockModel#' . $sum, $id, 'Unexpected ID for integer ID');

        $mock = new MockModel('foobar');
        $id = $mock->generateID($mock);
        $sum = substr(sha1('foobar'), 0, 10);
        $this->assertEquals('Wedeto_MockModel#' . $sum, $id, 'Unexpected ID for string ID');

        $mock = new MockModel(['123', '456']);
        $id = $mock->generateID($mock);
        $sum = substr(sha1('123-456'), 0, 10);
        $this->assertEquals('Wedeto_MockModel#' . $sum, $id, 'Unexpected ID for multi-valued ID');

        $mock = new MockModel(null);
        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Cannot generate an ID for an empty object");
        $id = $mock->generateID($mock);
    }

    public function testIsAllowed()
    {
        $loader = new MockEntityTestRuleLoader();
        $this->acl->setRuleLoader($loader);

        $role = new Role($this->acl, 'user');
        $entity = new Entity($this->acl, 'foo');

        $this->assertFalse($entity->isAllowed($role, Rule::READ));
        $this->assertFalse($entity->isAllowed($role, Rule::WRITE));
    }

    public function testGetPolicy()
    {
        $user1 = new Role($this->acl, "user1");
        $user2 = new Role($this->acl, "user2");
        $user3 = new Role($this->acl, "user3");

        $file = new Entity($this->acl, "file");
        $folder = new Entity($this->acl, "folder");

        $group = new Role($this->acl, "group1");

        $user1->setParents([$group]);
        $user2->setParents([$group]);
        $file->setParents([$folder]);

        $rules = [
            "folder" => [
                new Rule($this->acl, $folder, $this->acl->getRoot(Role::class), Rule::READ, Rule::ALLOW),
            ],
            "file" => [
                new Rule($this->acl, $file, $group, Rule::WRITE, Rule::ALLOW),
                new Rule($this->acl, $file, $user1, Rule::WRITE, Rule::DENY)
            ]
        ];

        $loader = new MockEntityTestRuleLoader();
        $loader->setMockRules($rules);
        $this->acl->setRuleLoader($loader);

        $this->assertEquals(Rule::ALLOW, $file->getPolicy($user1, Rule::READ));
        $this->assertEquals(Rule::DENY, $file->getPolicy($user1, Rule::WRITE));
        $this->assertEquals(Rule::ALLOW, $file->getPolicy($user2, Rule::WRITE));
        $this->assertEquals(Rule::UNDEFINED, $file->getPolicy($user3, Rule::WRITE));
        $this->assertEquals(Rule::ALLOW, $file->getPolicy($user3, Rule::READ));

        $this->assertTrue($file->isAllowed($user1, Rule::READ));
        $this->assertFalse($file->isAllowed($user1, Rule::WRITE));
        $this->assertTrue($file->isAllowed($user2, Rule::WRITE));
        $this->assertTrue($file->isAllowed($user3, Rule::READ));

        // This one has no rule, so it depends on the default policy
        $this->acl->setDefaultPolicy(Rule::ALLOW);
        $this->assertTrue($file->isAllowed($user3, Rule::WRITE));

        $this->acl->setDefaultPolicy(Rule::DENY);
        $this->assertFalse($file->isAllowed($user3, Rule::WRITE));
        
        // Check preferred policy setting
        $group2 = new Role($this->acl, "group2");
        $user2->setParents([$group, $group2]);
        
        // User 2 is child of group 1 and group 2. Group 1 allows write access
        // to file, so add a rule that denies group 2 from write access
        $rules['file'][] = new Rule($this->acl, $file, $group2, Rule::WRITE, Rule::DENY);
        $loader->setMockRules($rules);

        $file->resetRules();
        $folder->resetRules();

        // Now the outcome is determined by the preferred policy
        // First, prefer ALLOW
        $this->acl->setPreferredPolicy(Rule::ALLOW);
        $this->assertTrue($file->isAllowed($user2, Rule::WRITE));

        // Now, prefer DENY
        $this->acl->setPreferredPolicy(Rule::DENY);
        $this->assertFalse($file->isAllowed($user2, Rule::WRITE));
    }

    public function testInheritance()
    {
        $user1 = new Role($this->acl, "user1");
        $user2 = new Role($this->acl, "user2");
        $user3 = new Role($this->acl, "user3");

        $file = new Entity($this->acl, "file");
        $folder = new Entity($this->acl, "folder");

        $group = new Role($this->acl, "group1");

        $user1->setParents([$group]);
        $user2->setParents([$group]);
        $user3->setParents([$group]);
        $file->setParents([$folder]);

        $rule1 = new Rule($this->acl, $file, "", "", Rule::NOINHERIT);
        $rules = [
            "folder" => [
                new Rule($this->acl, $folder, $this->acl->getRoot(Role::class), Rule::READ, Rule::ALLOW),
                new Rule($this->acl, $file, $group, Rule::WRITE, Rule::ALLOW),
            ],
            "file" => [
                $rule1,
                new Rule($this->acl, $file, $user1, Rule::WRITE, Rule::DENY),
                new Rule($this->acl, $file, $user2, Rule::WRITE, Rule::ALLOW)
            ]
        ];

        $loader = new MockEntityTestRuleLoader();
        $loader->setMockRules($rules);
        $this->acl->setRuleLoader($loader);

        $this->assertEquals(Rule::DENY, $file->getPolicy($user1, Rule::WRITE));
        $this->assertEquals(Rule::ALLOW, $file->getPolicy($user2, Rule::WRITE));
        $this->assertEquals(Rule::UNDEFINED, $file->getPolicy($user3, Rule::WRITE));
        
        $rule1->setPolicy(Rule::INHERIT);
        $this->assertEquals(Rule::DENY, $file->getPolicy($user1, Rule::WRITE));
        $this->assertEquals(Rule::ALLOW, $file->getPolicy($user2, Rule::WRITE));
        $this->assertEquals(Rule::ALLOW, $file->getPolicy($user3, Rule::WRITE));
    }
}

class MockModel extends ACLModel
{
    protected $id;

    public function __construct($id)
    {
        $this->id = $id;
    }

    public function getID()
    {
        return $this->id;
    }
}

class MockEntityTestRuleLoader implements RuleLoaderInterface
{
    protected $mock_rules = [];

    public function setMockRules(array $rules)
    {
        $this->mock_rules = $rules;
    }

    public function loadRules(string $entity_id)
    {
        return $this->mock_rules[$entity_id] ?? [];
    }
}
