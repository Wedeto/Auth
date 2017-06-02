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
 * @covers Wedeto\Auth\ACL\RuleLoader
 */
class RuleLoaderTest extends TestCase
{
    public function setUp()
    {
        RuleLoader::setLoader();
    }

    public function tearDown()
    {
        RuleLoader::setLoader();
    }

    public function testSetRuleLoader()
    {
        RuleLoader::setLoader(new MockRuleLoaderInterfaceImplementation);

        $rules = RuleLoader::load('foobar');
        $this->assertEquals(['foo', 'bar'], $rules);
    }

    public function testNoSetRuleLoaderThrowsException()
    {
        $this->expectException(ACLException::class);
        $this->expectExceptionMessage('You need to set the loader before loading rules');
        RuleLoader::load('foobar');
    }
}

class MockRuleLoaderInterfaceImplementation implements RuleLoaderInterface
{
    public function loadRules(string $entity_id)
    {
        return ['foo', 'bar'];
    }
}
