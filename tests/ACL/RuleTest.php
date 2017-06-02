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

/**
 * @covers Wedeto\Auth\ACL\Rule
 */
class RuleTest extends TestCase
{
    public function setUp()
    {
        Entity::clearCache();
        Role::clearCache();
        Rule::setActionValidator();
    }

    public function testRuleSetup()
    {
        $obj = new Entity("object");
        $obj2 = new Entity("object2");
        $user = new Role("user");
        $user2 = new Role("user2");

        $r1 = new Rule("object", "user", Rule::READ, Rule::ALLOW);
        $r2 = new Rule("object", Role::getRoot(), Rule::WRITE, Rule::DENY);
        $r3 = new Rule("object", $user2, Rule::READ, Rule::ALLOW);
        $r4 = new Rule($obj2, "user2", Rule::READ, Rule::ALLOW);

        $this->assertInstanceOf(Rule::class, $r1);
        $this->assertInstanceOf(Rule::class, $r2);

        $this->assertInstanceOf(Entity::class, $r1->getEntity());
        $this->assertEquals('object', $r1->getEntity()->getID());
        $this->assertInstanceOf(Role::class, $r1->getRole());
        $this->assertEquals('user', $r1->getRole()->getID());
        $this->assertSame($r1->getEntity(), $r1->entity);
        $this->assertSame($r1->getRole(), $r1->role);
        $this->assertEquals(Rule::READ, $r1->action);
        $this->assertEquals(Rule::ALLOW, $r1->policy);

        $this->assertInstanceOf(Entity::class, $r2->getEntity());
        $this->assertEquals('object', $r2->getEntity()->getID());
        $this->assertInstanceOf(Role::class, $r2->getRole());
        $this->assertEquals('EVERYONE', $r2->getRole()->getID());
        $this->assertSame($r2->getEntity(), $r2->entity);
        $this->assertSame($r2->getRole(), Role::getRoot());
        $this->assertEquals(Rule::WRITE, $r2->action);
        $this->assertEquals(Rule::DENY, $r2->policy);

        $this->assertInstanceOf(Entity::class, $r3->getEntity());
        $this->assertEquals('object', $r3->getEntity()->getID());
        $this->assertInstanceOf(Role::class, $r3->getRole());
        $this->assertSame($user2, $r3->getRole());
        $this->assertSame($r3->getEntity(), $r3->entity);
        $this->assertSame($r3->getRole(), $r3->role);
        $this->assertEquals(Rule::WRITE, $r2->action);
        $this->assertEquals(Rule::DENY, $r2->policy);

        $this->assertInstanceOf(Entity::class, $r4->getEntity());
        $this->assertSame("object2", $r4->getEntity()->getID());
        $this->assertInstanceOf(Role::class, $r4->getRole());
        $this->assertSame($user2, $r4->getRole());
        $this->assertSame($r4->getEntity(), $r4->entity);
        $this->assertSame($r4->getRole(), $r4->role);
        $this->assertEquals(Rule::READ, $r4->action);
        $this->assertEquals(Rule::ALLOW, $r4->policy);
    }

    public function testUseActionValidator()
    {
        $val = new MockActionValidator;
        $val->setResult(true);

        Rule::setActionValidator($val);
        
        $rule = new Rule("object", "user", Rule::READ, Rule::ALLOW);
        $this->assertEquals(1, $val->call_count);

        $val->setResult(false);
        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Action can not be validated: rejected");
        $rule->setAction('foobar');
    }

    public function testInvalidField()
    {
        $obj = new Entity("object");
        $user = new Role("user");

        $rule = new Rule($obj, $user, Rule::READ, Rule::ALLOW); 
        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Invalid field for Rule: foo");
        $rule->foo;
    }

    public function testDefaultAndPreferredPolicy()
    {
        Rule::setDefaultPolicy(Rule::ALLOW);
        Rule::setPreferredPolicy(Rule::ALLOW);
        $this->assertEquals(Rule::ALLOW, Rule::getDefaultPolicy());
        Rule::setDefaultPolicy(Rule::DENY);
        Rule::setPreferredPolicy(Rule::ALLOW);
        $this->assertEquals(Rule::DENY, Rule::getDefaultPolicy());

        Rule::setPreferredPolicy(Rule::ALLOW);
        Rule::setDefaultPolicy(Rule::ALLOW);
        $this->assertEquals(Rule::ALLOW, Rule::getPreferredPolicy());
        Rule::setPreferredPolicy(Rule::DENY);
        Rule::setDefaultPolicy(Rule::ALLOW);
        $this->assertEquals(Rule::DENY, Rule::getPreferredPolicy());

        Rule::setDefaultPolicy("DENY");
        $this->assertEquals(Rule::DENY, Rule::getDefaultPolicy());

        Rule::setDefaultPolicy("ALLOW");
        $this->assertEquals(Rule::ALLOW, Rule::getDefaultPolicy());

        Rule::setPreferredPolicy("DENY");
        $this->assertEquals(Rule::DENY, Rule::getPreferredPolicy());

        Rule::setPreferredPolicy("ALLOW");
        $this->assertEquals(Rule::ALLOW, Rule::getPreferredPolicy());

        $thrown = false;
        try
        {
            Rule::setDefaultPolicy("FOO");
        }
        catch (ACLException $e)
        {
            $this->assertContains("Default policy should be either Rule::ALLOW or Rule::DENY", $e->getMessage());
            $thrown = true;
        }
        $this->assertTrue($thrown);

        $thrown = false;
        try
        {
            Rule::setPreferredPolicy("FOO");
        }
        catch (ACLException $e)
        {
            $this->assertContains("Preferred policy should be either Rule::ALLOW or Rule::DENY", $e->getMessage());
            $thrown = true;
        }
        $this->assertTrue($thrown);
    }

    public function testGetSetRecord()
    {
        $rule = new Rule("object", "user", Rule::READ, Rule::ALLOW);
        $data = new \stdClass;
        $this->assertSame($rule, $rule->setRecord($data));
        $this->assertSame($data, $rule->getRecord());
    }

    public function testConstructingWithRoleAndNoInheritThrowsException()
    {
        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Rule::NOINHERIT can not be used in combination with a role");
        $rule = new Rule("object", "user", "", Rule::NOINHERIT);
    }

    public function testConstructingWithActionAndNoInheritThrowsException()
    {
        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Rule::NOINHERIT can not be used in combination with an action");
        $rule = new Rule("object", "", Rule::READ, Rule::NOINHERIT);
    }

    public function testSettingRoleOnNoInheritRuleThrowsException()
    {
        $rule = new Rule("object", "", "", Rule::NOINHERIT);

        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Rule::NOINHERIT can not be used in combination with a role");
        $rule->setRole("user");
    }

    public function testSettingActionOnNoInheritRuleThrowsException()
    {
        $rule = new Rule("object", "", "", Rule::NOINHERIT);

        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Rule::NOINHERIT can not be used in combination with an action");
        $rule->setAction(Rule::WRITE);
    }

    public function testSettingInvalidRoleTypeThrowsException()
    {
        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Role-ID must be a Role or a scalar");
        $rule = new Rule("object", [], "", Rule::NOINHERIT);
    }

    public function testSettingInvalidEntityTypeThrowsException()
    {
        $this->expectException(ACLException::class);
        $this->expectExceptionMessage("Entity-ID must be an Entity or a scalar");
        $rule = new Rule([], "user", "", Rule::NOINHERIT);
    }

    public function testSettingValidAndInvalidPolicies()
    {
        $policies = [
            Rule::ALLOW => true,
            Rule::DENY => true,
            Rule::INHERIT => true,
            Rule::NOINHERIT => true,
            1000 => false,
            null => false
        ];

        foreach ($policies as $pol => $valid)
        {
            $thrown = false;
            try
            {
                $rule = new Rule("object", "", "", $pol);
            }
            catch (ACLException $e)
            {
                $thrown = true;
            }
            catch (\TypeError $e)
            {
                $thrown = true;
            }
            $this->assertEquals(!$valid, $thrown);
        }
    }
}

class MockActionValidator implements ActionValidatorInterface
{
    protected $result = true;
    public $call_count = 0;

    public function setResult(bool $result)
    {
        $this->result = $result;
    }

    public function isValid(string $action)
    {
        ++$this->call_count;
        return $this->result ? true : "rejected";
    }
}
