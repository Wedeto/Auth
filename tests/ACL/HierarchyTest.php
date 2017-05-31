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
 * @covers Wedeto\Auth\ACL\Hierarchy
 */
class HierarchyTest extends TestCase
{
    public function setUp()
    {
        MockHierarchy::clearCache();
        Mock2Hierarchy::clearCache();
    }

    public function testConstructionAndComparison()
    {
        $one = new MockHierarchy('one');
        $two = new MockHierarchy('two');
        $one_dup = new MockHierarchy('one');

        $this->assertTrue($one->is($one_dup));
        $this->assertTrue($one_dup->is($one));
        $this->assertFalse($one->is($two));
        $this->assertFalse($two->is($one));

        // Test differing classes
        $other = new Mock2Hierarchy('one');
        $this->assertFalse($other->is($one));
        $this->assertFalse($other->is($two));
        $this->assertFalse($other->is($one_dup));
        $this->assertTrue($other->is($other));

        // Test that getInstance is no-op when provided with a hierarchy
        $this->assertSame($one, MockHierarchy::getInstance($one));
        
        // Test that getInstance throws exception when differing class of parameter
        $thrown = false;
        try
        {
            Hierarchy::getInstance($one);
        }
        catch (ACLException $e)
        {
            $this->assertContains('must be a scalar', $e->getMessage());
            $thrown = true;
        }
        $this->assertTrue($thrown);

        $this->assertSame($one_dup, MockHierarchy::getInstance('one'));
        $this->assertSame($two, MockHierarchy::getInstance('two'));

        $root = MockHierarchy::getInstance('MOCKROOT');
        $this->assertInstanceOf(MockHierarchy::class, $root);
        $this->assertSame(MockHierarchy::getRoot(), $root);

        
        $thrown = false;
        try
        {
            MockHierarchy::getInstance('three');
        }
        catch (ACLException $e)
        {
            $this->assertContains('Element-ID three is unknown for', $e->getMessage());
            $thrown = true;
        }
        $this->assertTrue($thrown);

        $this->assertTrue(MockHierarchy::hasInstance('one'));
        $this->assertTrue(MockHierarchy::hasInstance('two'));
        $this->assertTrue(MockHierarchy::hasInstance('MOCKROOT'));
        $this->assertFalse(MockHierarchy::hasInstance('three'));

        MockHierarchy::clearCache();
        $this->assertFalse(MockHierarchy::hasInstance('one'));
        $this->assertFalse(MockHierarchy::hasInstance('two'));
        $this->assertTrue(MockHierarchy::hasInstance('MOCKROOT'));
        $this->assertFalse(MockHierarchy::hasInstance('three'));
    }

    public function testAncestry()
    {
        $a1 = new MockHierarchy('a1');
        $a2 = new MockHierarchy('a2');
        $b1 = new MockHierarchy('b1');
        $b2 = new MockHierarchy('b2');

        $c = new MockHierarchy('c');
        $d = new MockHierarchy('d');

        $other = new Mock2Hierarchy('d');

        $root = MockHierarchy::getRoot();

        $a2->setParents('a1');
        $b2->setParents($b1);

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

}

class MockHierarchy extends Hierarchy
{
    protected static $root = 'MOCKROOT';

    public function __construct($id)
    {
        $this->id = $id;
        self::$database[__CLASS__][$id] = $this;
    }
}

class Mock2Hierarchy extends Hierarchy
{
    protected static $root = 'MOCKROOT';

    public function __construct($id)
    {
        $this->id = $id;
        self::$database[__CLASS__][$id] = $this;
    }
}
