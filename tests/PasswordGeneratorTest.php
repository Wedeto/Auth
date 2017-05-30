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

/**
 * @covers Wedeto\Auth\PasswordGenerator
 */
class PasswordGeneratorTest extends TestCase
{
    protected $files = [];

    public function tearDown()
    {
        foreach ($this->files as $f)
            if (strpos($f, 'wedetotest') !== false && file_exists($f))
                unlink($f);
    }

    public function testGeneratorWithoutCharachters()
    {
        $gen = new PasswordGenerator;
        $this->expectException(\UnderflowException::class);
        $this->expectExceptionMessage("First add characters used to generate");
        $pwd = $gen->generatePassword(5);
    }

    public function testGenerateZeroLength()
    {
        $gen = new PasswordGenerator;
        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage("Cannot generate zero-length passwords");
        $pwd = $gen->generatePassword(0);
    }

    public function testGeneratorWithInvalidCharacters()
    {
        $gen = new PasswordGenerator;
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid type");
        $gen->addCharacters([new \stdClass]);
    }

    public function testGeneratorWithMoreInvalidCharacters()
    {
        $gen = new PasswordGenerator;
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid type");
        $gen->addCharacters(new \DateTime);
    }

    public function testGeneratorWithAlphaCharacters()
    {
        $gen = new PasswordGenerator;
        $gen->addAlpha();

        $generated = [];
        for ($i = 0; $i < 100; ++$i)
        {
            $pwd = $gen->generatePassword(24);
            $this->assertEquals(0, preg_match('/[^a-zA-Z]/', $pwd));
            $this->assertFalse(isset($generated[$pwd]));
            $generated[$pwd] = true;
        }
    }

    public function testGeneratorWithAlphaNumericCharacters()
    {
        $gen = new PasswordGenerator;
        $gen->addAlnum();

        for ($l = 4; $l <= 24; $l += 2)
        {
            $generated = [];
            for ($i = 0; $i < 25; ++$i)
            {
                $pwd = $gen->generatePassword($l);
                $this->assertEquals($l, strlen($pwd), "Password does not have a length of $l");
                $this->assertEquals(0, preg_match('/[^a-zA-Z0-9]/', $pwd), "Password '$pwd' contains unspecified characters");
                $this->assertFalse(isset($generated[$pwd]), "Password was generated before");
                $generated[$pwd] = true;
            }
        }
    }

    public function testGeneratorWithAlphaAndCustomCharacters()
    {
        $gen = new PasswordGenerator;
        $gen
            ->addAlpha()
            ->addCharacters(['?', '$', '(', ')']);

        for ($l = 4; $l <= 24; $l += 2)
        {
            $generated = [];
            for ($i = 0; $i < 25; ++$i)
            {
                $pwd = $gen->generatePassword($l);
                $this->assertEquals($l, strlen($pwd), "Password does not have a length of $l");
                $this->assertEquals(0, preg_match('/[^a-zA-Z?$()]/', $pwd), "Password '$pwd' contains unspecified characters");
                $this->assertFalse(isset($generated[$pwd]), "Password was generated before");
                $generated[$pwd] = true;
            }
        }
    }

    public function testGeneratePassPhrase()
    {
        $valid_words = [
            "foo",
            "bar",
            "baz",
            "boo"
        ];

        $tmp = tempnam(sys_get_temp_dir(), "wedetotest");
        $this->files[] = $tmp;
        file_put_contents($tmp, "foo\nbar\nbaz\nboo\nfoobar\n");

        $gen = new PasswordGenerator;
        $gen->loadDictionary($tmp, false, "/^[a-z]{3}$/");

        for ($l = 1; $l < 3; ++$l)
        {
            for ($i = 0; $i < 25; ++$i)
            {
                $pwd = $gen->generatePassphrase($l);
                $words = explode(" ", $pwd);
                $this->assertEquals($l, count($words));
                $this->assertEquals($words, array_unique($words));
                foreach ($words as $word)
                    $this->assertTrue(in_array($word, $valid_words, true), "Invalid word: $word");
                $this->assertFalse(in_array('foobar', $words), "Unmatching word used");
            }
        }

        $this->expectException(\UnderflowException::class);
        $this->expectExceptionMessage("Not enough words loaded");
        $gen->generatePassphrase(count($valid_words) + 1);
    }
    
    public function testLoadNonExistingDictionary()
    {
        $gen = new PasswordGenerator;
        $this->expectException(IOException::class);
        $this->expectExceptionMessage("Cannot open file a.file.that.should.hopefully.not.exist");
        $gen->loadDictionary('a.file.that.should.hopefully.not.exist');
    }

    public function testLoadDictionaryWithInvalidRegexp()
    {
        $gen = new PasswordGenerator;

        $tmp = tempnam(sys_get_temp_dir(), "wedetotest");
        $this->files[] = $tmp;
        file_put_contents($tmp, "foo\nbar\nbaz\nboo\nfoobar\n");

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid regexp: /faultyrege]");
        $gen->loadDictionary($tmp, false, '/faultyrege]');
    }

    public function testLoadDictionaryWithUnmatchingRegex()
    {
        $gen = new PasswordGenerator;

        $tmp = tempnam(sys_get_temp_dir(), "wedetotest");
        $this->files[] = $tmp;
        file_put_contents($tmp, "foo\nbar\nbaz\nboo\nfoobar\n");

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("File $tmp contains no words that match");
        $gen->loadDictionary($tmp, false, '/^[a-z]{4}$/');
        var_Dump($gen);
    }

    public function testLoadDictionaryFromInvalidFile()
    {
        // WMV header  
        $wmv_header =  chr(0x30) . chR(0x26) . chr(0xb2) . chR(0x75) . chr(0x8e)
            . chr(0x66) . chr(0xcf) . chr(0x11) . chr(0xa6) . chr(0xd9) . chr(0x00)
            . chr(0xaa) . chr(0x00) . chr(0x62) . chr(0xce) . chr(0x6c);

        $tmp = tempnam(sys_get_temp_dir(), "wedetotest");
        $this->files[] = $tmp;
        file_put_contents($tmp, $wmv_header);

        $gen = new PasswordGenerator;
        $this->expectException(IOException::class);
        $this->expectExceptionMessage("$tmp does not appear to contain text");
        $gen->loadDictionary($tmp);
    }
}
