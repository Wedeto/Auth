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

namespace Wedeto\Auth\ACL;

use PHPUnit\Framework\TestCase;

use Wedeto\Auth\ACL\Exception as ACLException;
use Wedeto\DB\DAO;

/**
 * @covers Wedeto\Auth\ACL\Entity
 */
class EntityTest extends TestCase
{
    public function setUp()
    {
        Entity::clearCache();
        Role::clearCache();
    }

    public function testConstructionWithIDWorks()
    {
        $entity = new Entity('foo');
        $this->assertEquals('foo', $entity->getID());

        $entity = new Entity('bar');
        $this->assertEquals('bar', $entity->getID());
    }

    public function testConstructWithNonScalar()
    {
        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Entity-ID must be a scalar");
        $entity = new Entity(['foo']);
    }

    public function testDuplicateConstructionThrowsException()
    {
        $foo1 = new Entity('foo');

        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Duplicate entity: foo");
        $foo2 = new Entity('foo');
    }

    public function testGenerateID()
    {
        $mock = new MockDAO(123);
        $id = Entity::generateID($mock);
        $sum = substr(sha1('123'), 0, 10);
        $this->assertEquals('Wedeto_MockDAO#' . $sum, $id, 'Unexpected ID for integer ID');

        $mock = new MockDAO('foobar');
        $id = Entity::generateID($mock);
        $sum = substr(sha1('foobar'), 0, 10);
        $this->assertEquals('Wedeto_MockDAO#' . $sum, $id, 'Unexpected ID for string ID');

        $mock = new MockDAO(['123', '456']);
        $id = Entity::generateID($mock);
        $sum = substr(sha1('123-456'), 0, 10);
        $this->assertEquals('Wedeto_MockDAO#' . $sum, $id, 'Unexpected ID for multi-valued ID');

        $mock = new MockDAO(null);
        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Cannot generate an ID for an empty object");
        $id = Entity::generateID($mock);
    }

    public function testIsAllowed()
    {
        $loader = new MockEntityTestRuleLoader();
        RuleLoader::setLoader($loader);

        $role = new Role('user');
        $entity = new Entity('foo');

        $this->assertFalse($entity->isAllowed($role, Rule::READ));
        $this->assertFalse($entity->isAllowed($role, Rule::WRITE));
    }

    public function testGetPolicy()
    {
        $user1 = new Role("user1");
        $user2 = new Role("user2");
        $user3 = new Role("user3");

        $file = new Entity("file");
        $folder = new Entity("folder");

        $group = new Role("group1");

        $user1->setParents($group);
        $user2->setParents($group);
        $file->setParents($folder);

        $rules = [
            "folder" => [
                new Rule($folder, Role::getRoot(), Rule::READ, Rule::ALLOW),
            ],
            "file" => [
                new Rule($file, $group, Rule::WRITE, Rule::ALLOW),
                new Rule($file, $user1, Rule::WRITE, Rule::DENY)
            ]
        ];

        $loader = new MockEntityTestRuleLoader();
        $loader->setMockRules($rules);
        RuleLoader::setLoader($loader);

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
        Rule::setDefaultPolicy(Rule::ALLOW);
        $this->assertTrue($file->isAllowed($user3, Rule::WRITE));

        Rule::setDefaultPolicy(Rule::DENY);
        $this->assertFalse($file->isAllowed($user3, Rule::WRITE));
        
        // Check preferred policy setting
        $group2 = new Role("group2");
        $user2->setParents([$group, $group2]);
        
        // User 2 is child of group 1 and group 2. Group 1 allows write access
        // to file, so add a rule that denies group 2 from write access
        $rules['file'][] = new Rule($file, $group2, Rule::WRITE, Rule::DENY);
        $loader->setMockRules($rules);

        $file->resetRules();
        $folder->resetRules();

        // Now the outcome is determined by the preferred policy
        // First, prefer ALLOW
        Rule::setPreferredPolicy(Rule::ALLOW);
        $this->assertTrue($file->isAllowed($user2, Rule::WRITE));

        // Now, prefer DENY
        Rule::setPreferredPolicy(Rule::DENY);
        $this->assertFalse($file->isAllowed($user2, Rule::WRITE));
    }

    public function testInheritance()
    {
        $user1 = new Role("user1");
        $user2 = new Role("user2");
        $user3 = new Role("user3");

        $file = new Entity("file");
        $folder = new Entity("folder");

        $group = new Role("group1");

        $user1->setParents($group);
        $user2->setParents($group);
        $user3->setParents($group);
        $file->setParents($folder);

        $rule1 = new Rule($file, "", "", Rule::NOINHERIT);
        $rules = [
            "folder" => [
                new Rule($folder, Role::getRoot(), Rule::READ, Rule::ALLOW),
                new Rule($file, $group, Rule::WRITE, Rule::ALLOW),
            ],
            "file" => [
                $rule1,
                new Rule($file, $user1, Rule::WRITE, Rule::DENY),
                new Rule($file, $user2, Rule::WRITE, Rule::ALLOW)
            ]
        ];

        $loader = new MockEntityTestRuleLoader();
        $loader->setMockRules($rules);
        RuleLoader::setLoader($loader);

        $this->assertEquals(Rule::DENY, $file->getPolicy($user1, Rule::WRITE));
        $this->assertEquals(Rule::ALLOW, $file->getPolicy($user2, Rule::WRITE));
        $this->assertEquals(Rule::UNDEFINED, $file->getPolicy($user3, Rule::WRITE));
        
        $rule1->setPolicy(Rule::INHERIT);
        $this->assertEquals(Rule::DENY, $file->getPolicy($user1, Rule::WRITE));
        $this->assertEquals(Rule::ALLOW, $file->getPolicy($user2, Rule::WRITE));
        $this->assertEquals(Rule::ALLOW, $file->getPolicy($user3, Rule::WRITE));
    }
}

class MockDAO extends DAO
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
