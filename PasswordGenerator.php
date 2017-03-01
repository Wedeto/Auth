<?php
/*
This is part of WASP, the Web Application Software Platform.
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

namespace WASP\Auth;

use InvalidArgumentException;
use UnderflowException;
use WASP\IOException;
use function WASP\is_array_like;

/**
 * Generate random passwords or passphrases.
 * This class will generate passwords from a set of specified characters,
 * or load a dictionary of words and select a number of random words from this
 * list matching a pattern to generate a passphrase.
 */
class PasswordGenerator
{
    protected $dictionaries = array();
    protected $characters = array();

    /**
     * Add one or more characters to the list of eligible characters
     * @param string|array $chars The characters to add
     * @return WASP\Auth\PasswordGenerator Provides fluent interface
     */
    public function addCharacters($chars)
    {
        if (is_array_like($chars))
        {
            foreach ($chars as $char)
                $this->characters[$char] = true;
        }
        elseif (is_string($chars))
        {
            for ($i = 0; $i < mb_strlen($chars); ++$i)
                $this->characters[mb_substr($chars, $i, 1)] = true;
        }
        else
        {
            throw new InvalidArgumentException("Invalid type: " . $chars);
        }
        return $this;
    }

    /**
     * Add the latin alphabet to the list of eligible characters
     * @return WASP\Auth\PasswordGenerator Provides fluent interface
     */
    public function addAlpha()
    {
        return $this->addCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    }

    /**
     * Add the numbers 0-9 to the list of elgiible characters
     * @return WASP\Auth\PasswordGenerator Provides fluent interface
     */
    public function addNumbers()
    {
        return $this->addCharacters("0123456789");
    }

    /**
     * Add the latin alphabet and numbers to the list of eligible characters
     * @return WASP\Auth\PasswordGenerator Provides fluent interface
     */
    public function addAlnum()
    {
        return $this->addAlpha()->addNumbers();
    }

    /**
     * Generate a password of the specified length
     */
    public function generatePassword(int $length = 8)
    {
        if ($length <= 0)
            throw new DomainException("Cannot generate zero-length passwords");

        $chars = array_keys($this->characters);
        $max_val = mb_strlen($chars) - 1;
        $pwd = "";
        for ($i = 0; $i < $length; ++$i)
        {
            $pos = random_int(0, $max_val);
            $pwd .= mb_substr($chars, $pos, 1);
        }
        return $pwd;
    }

    /**
     * Load a dictionary file for passphrase generation
     * @param string $filename The file to read. Can be a full path or a name
     *                         of a dictionary in /usr/share/dict
     * @param bool $append True to add to the list of words, false to replace
     *                     it. Defauls to false
     * @param string $regexp A regular expression to match each word to. Can be
     *                       empty. Defaults to allowing on lowercase latin alphabet.
     * @return WASP\Auth\PasswordGenerator Provides fluent interface
     * @throws InvalidArgumentException When an invalid regular expression is
     *                                  given or no words match it.
     * @throws WASP\IOException When the file is not readable
     */
    public function loadDictionary(string $filename, $append = false, $regexp = "/^[a-z]{4,6}$/")
    {
        if (!file_exists($filename) || !is_readable($filename))
        {
            $fn = "/usr/share/dict/" . $filename;
            if (!file_exists($fn))
                throw new IOException("Cannot open file $filename and dictionary $fn does not exist");
            $filename = $fn;
        }

        $cnt = mime_content_type($filename);
        if (substr($cnt, 0, 4) !== "text")
            throw new IOException("$filename does not appear to contain text");

        $contents = file_get_contents($fn);
        $lines = explode("\n", $contents);
        if (!$append)
            $this->dictionary = array();

        $nwords = 0;
        try
        {
            foreach ($lines as $line)
            {
                if (empty($regexp) || preg_match($regexp, $line))
                {
                    $this->dictionary[] = $line;
                    ++$nwords;
                }
            }
        }
        catch (ErrorException $e)
        {
            throw new InvalidArgumentException("Invalid regexp: $regexp");
        }

        if ($nwords === 0)
            throw new InvalidArgumentException("File $filename contains no words that match $regexp");

        return $this;
    }

    /**
     * Generate a passphrase of the specified amount of words
     * @param int $num_words The number of words in the passphase
     * @retuern string The generated passprase
     * @throws UnderflowException If no or not enough words have been loaded
     */
    public function generatePassphrase($num_words = 4)
    {
        if (count($this->dictionary) < $num_words)
        {
            throw new UnderflowException(
                "Not enough words loaded to generate a passphrase of $num_words words"
            );
        }

        $words = array();
        $attempt = 0;
        while (count($words) < $num_words)
        {
            ++$attempt;
            $s = random_int(0, count($this->dictionary));
            $word = $this->dictionary[$s];
            if (!in_array($word, $words) || $attempt > 4 * $num_words)
                $words[] = $word;
        }
        return implode(" ", $words);
    }
}
