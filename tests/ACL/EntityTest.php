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
    }

    public function testConstructionWithIDWorks()
    {
        $entity = new Entity('foo');
        $this->assertEquals('foo', $entity->getEntityID());

        $entity = new Entity('bar');
        $this->assertEquals('bar', $entity->getEntityID());
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
        $this->assertEquals('Wedeto_MockDAO#' . $sum, $id, 'Unexpected ID for multi-valued ID');
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
