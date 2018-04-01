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

/**
 * @covers Wedeto\Auth\ACL\Hierarchy
 * @covers Wedeto\Auth\ACL\ACL
 */
class HierarchyTest extends TestCase
{
    public function setUp()
    {
        $rl = $this->prophesize(RuleLoaderInterface::class);
        $this->rl = $rl->reveal();
        $this->acl = new ACL($this->rl);
    }

    public function testConstructionAndComparison()
    {
        $one = new MockHierarchy($this->acl, 'one');
        $two = new MockHierarchy($this->acl, 'two');
        $one_dup = new MockHierarchy($this->acl, 'one');

        $this->assertEquals('one', $one->getID());
        $this->assertEquals('two', $two->getID());

        $this->assertTrue($one->is($one_dup));
        $this->assertTrue($one_dup->is($one));
        $this->assertFalse($one->is($two));
        $this->assertFalse($two->is($one));

        // Test differing classes
        $other = new Mock2Hierarchy($this->acl, 'one');
        $this->assertFalse($other->is($one));
        $this->assertFalse($other->is($two));
        $this->assertFalse($other->is($one_dup));
        $this->assertTrue($other->is($other));

        // Test that getInstance is no-op when provided with a hierarchy
        $this->assertSame($one, $this->acl->getInstance(MockHierarchy::class, $one));
        
        $this->assertSame($one_dup, $this->acl->getInstance(MockHierarchy::class, 'one'));
        $this->assertSame($two, $this->acl->getInstance(MockHierarchy::class, 'two'));

        $root = $this->acl->getInstance(MockHierarchy::class, 'MOCKROOT');
        $this->assertInstanceOf(MockHierarchy::class, $root);
        $this->assertSame($one->getRoot(), $root);

        
        $thrown = false;
        try
        {
            $this->acl->getInstance(MockHierarchy::class, 'three');
        }
        catch (ACLException $e)
        {
            $this->assertContains('Element-ID \'three\' is unknown for', $e->getMessage());
            $thrown = true;
        }
        $this->assertTrue($thrown);

        $this->assertTrue($this->acl->hasInstance(MockHierarchy::class, 'one'));
        $this->assertTrue($this->acl->hasInstance(MockHierarchy::class, 'two'));
        $this->assertTrue($this->acl->hasInstance(MockHierarchy::class, 'MOCKROOT'));
        $this->assertFalse($this->acl->hasInstance(MockHierarchy::class, 'three'));

        $this->acl = new ACL($this->rl);
        $this->assertFalse($this->acl->hasInstance(MockHierarchy::class, 'one'));
        $this->assertFalse($this->acl->hasInstance(MockHierarchy::class, 'two'));
        $this->assertFalse($this->acl->hasInstance(MockHierarchy::class, 'MOCKROOT'));
        $this->assertFalse($this->acl->hasInstance(MockHierarchy::class, 'three'));
    }

    public function testAncestry()
    {
        $a1 = new MockHierarchy($this->acl, 'a1');
        $a2 = new MockHierarchy($this->acl, 'a2');
        $b1 = new MockHierarchy($this->acl, 'b1');
        $b2 = new MockHierarchy($this->acl, 'b2');

        $c = new MockHierarchy($this->acl, 'c');
        $d = new MockHierarchy($this->acl, 'd');

        $other = new Mock2Hierarchy($this->acl, 'd');

        $root = $c->getRoot();

        $a2->setParents(['a1']);
        $b2->setParents([$b1]);

        $c->setParents([$a2, 'b1']);

        $d->setParents([]);

        $this->assertEquals(1, $root->isAncestorOf($a1));
        $this->assertEquals(2, $root->isAncestorOf($a2));
        $this->assertEquals(1, $root->isAncestorOf($b1));
        $this->assertEquals(2, $root->isAncestorOf($b2));
        $this->assertEquals(2, $root->isAncestorOf($c));
        $this->assertEquals(1, $root->isAncestorOf($d));
        $this->assertEquals(0, $root->isAncestorOf($other));

        $this->assertEquals(1, $a1->isOffspringOf($root));
        $this->assertEquals(2, $a2->isOffspringOf($root));
        $this->assertEquals(1, $b1->isOffspringOf($root));
        $this->assertEquals(2, $b2->isOffspringOf($root));
        $this->assertEquals(2, $c->isOffspringOf($root));
        $this->assertEquals(1, $d->isOffspringOf($root));
        $this->assertEquals(0, $other->isOffspringOf($root));

        $this->assertEquals(0, $a1->isOffspringOf($a1));
        $this->assertEquals(0, $a1->isOffspringOf($a2));
        $this->assertEquals(0, $a1->isOffspringOf($b1));
        $this->assertEquals(0, $a1->isOffspringOf($b2));
        $this->assertEquals(0, $a1->isOffspringOf($c));

        $this->assertEquals(0, $a1->isAncestorOf($a1));
        $this->assertEquals(1, $a1->isAncestorOf($a2));
        $this->assertEquals(0, $a1->isAncestorOf($b1));
        $this->assertEquals(0, $a1->isAncestorOf($b2));
        $this->assertEquals(2, $a1->isAncestorOf($c));

        $this->assertEquals(1, $a2->isOffspringOf($a1));
        $this->assertEquals(0, $a2->isOffspringOf($a2));
        $this->assertEquals(0, $a2->isOffspringOf($b1));
        $this->assertEquals(0, $a2->isOffspringOf($b2));
        $this->assertEquals(0, $a2->isOffspringOf($c));

        $this->assertEquals(0, $a2->isAncestorOf($a1));
        $this->assertEquals(0, $a2->isAncestorOf($a2));
        $this->assertEquals(0, $a2->isAncestorOf($b1));
        $this->assertEquals(0, $a2->isAncestorOf($b2));
        $this->assertEquals(1, $a2->isAncestorOf($c));

        $this->assertEquals(0, $b1->isOffspringOf($a1));
        $this->assertEquals(0, $b1->isOffspringOf($a2));
        $this->assertEquals(0, $b1->isOffspringOf($b1));
        $this->assertEquals(0, $b1->isOffspringOf($b2));
        $this->assertEquals(0, $b1->isOffspringOf($c));

        $this->assertEquals(0, $b1->isAncestorOf($a1));
        $this->assertEquals(0, $b1->isAncestorOf($a2));
        $this->assertEquals(0, $b1->isAncestorOf($b1));
        $this->assertEquals(1, $b1->isAncestorOf($b2));
        $this->assertEquals(1, $b1->isAncestorOf($c));

        $this->assertEquals(0, $b2->isOffspringOf($a1));
        $this->assertEquals(0, $b2->isOffspringOf($a2));
        $this->assertEquals(1, $b2->isOffspringOf($b1));
        $this->assertEquals(0, $b2->isOffspringOf($b2));
        $this->assertEquals(0, $b2->isOffspringOf($c));

        $this->assertEquals(0, $b2->isAncestorOf($a1));
        $this->assertEquals(0, $b2->isAncestorOf($a2));
        $this->assertEquals(0, $b2->isAncestorOf($b1));
        $this->assertEquals(0, $b2->isAncestorOf($b2));
        $this->assertEquals(0, $b2->isAncestorOf($c));

        $this->assertEquals(2, $c->isOffspringOf($a1));
        $this->assertEquals(1, $c->isOffspringOf($a2));
        $this->assertEquals(1, $c->isOffspringOf($b1));
        $this->assertEquals(0, $c->isOffspringOf($b2));
        $this->assertEquals(0, $c->isOffspringOf($c));

        $this->assertEquals(0, $c->isAncestorOf($a1));
        $this->assertEquals(0, $c->isAncestorOf($a2));
        $this->assertEquals(0, $c->isAncestorOf($b1));
        $this->assertEquals(0, $c->isAncestorOf($b2));
        $this->assertEquals(0, $c->isAncestorOf($c));
    }

    public function testGetParentsWithLoader()
    {
        $i1 = new MockHierarchy($this->acl, 'foo');
        $i1->setParents(['bar']);

        $counter = new \stdClass;
        $counter->cnt = 0;

        $loader = new MockRuleLoader($this->acl);
        $parents = $i1->getParents($loader);

        $this->assertEquals(1, $loader->counter);
        $this->assertEquals(1, count($parents));
        $this->assertEquals('bar', $parents[0]->getID());
    }
}

class MockHierarchy extends Hierarchy
{
    protected static $root = 'MOCKROOT';

    public function __construct(ACL $acl, $id)
    {
        parent::__construct($acl);
        $this->id = $id;
        $acl->setInstance($this);
    }
}

class Mock2Hierarchy extends Hierarchy
{
    protected static $root = 'MOCKROOT';

    public function __construct(ACL $acl, $id)
    {
        parent::__construct($acl);
        $this->id = $id;
        $acl->setInstance($this);
    }
}

class MockRuleLoader implements LoaderInterface
{
    public $counter = 0;
    public $acl;
    
    function __construct(ACL $acl)
    {
        $this->acl = $acl;
    }

    function load($id, string $class)
    {
        ++$this->counter;
        return new MockHierarchy($this->acl, $id);
    }
}
