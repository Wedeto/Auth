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

/**
 * Base class for Role and Entity that manages the
 * parent-child relations between Entities and Roles.
 */
abstract class Hierarchy
{
    /** Associative array of id => element pairs of parent elements */
    protected $parents = array();
    /** The ID of the current element */
    protected $id = null;
    /** Storage for all elements retrieved thusfar */
    protected static $database = array();
    /** Subclasses should define the name of the root element here */
    protected static $root;

    /** 
     * Check if the objects are referring to the same element.
     * @return boolean True if both elements are the same class and ID, false otherwise
     */
    public function is(Hierarchy $element)
    {
        if (get_class($this) !== get_class($element))
            return false;
        return $this->id === $element->id;
    }

    /**
     * Check if the current element is an ancestor of the specified element
     * @param $element Hierarchy The element to check
     * @param $loader callable A loader that can be used to load additional instances
     * @return boolean True when the current Entity is an ancestor of $element, false otherwise
     */
    public function isAncestorOf(Hierarchy $element, $loader = null)
    {
        return $element->isOffspring($this, $loader);
    }

    /**
     * Check if the current element is offspring of the specified element
     * @param $role Hierarchy The element to check
     * @param $loader callable A loader that can be used to load additional instances
     * @return integer The number of generation leves between the $this and $element - 0 if they're not related
     */
    public function isOffspringOf(Hierarchy $element, $loader = null)
    {
        if (get_class($element) !== get_class($this))
            return 0;

        $stack = array();
        $parents = $this->getParents($loader);
        foreach ($parents as $p)
            $stack[] = array(1, $p);

        $seen = array();
        $level = 0;
        while (!empty($stack))
        {
            list($level, $cur) = array_shift($stack);

            // Avoid infinite cycles
            if (isset($seen[$el->id]))
                continue;

            // If the ancestor is the requested element, we found our answer
            if ($cur->id === $element->id)
                return $level;

            // Add all parents of this element to the stack
            foreach ($cur->getParents($loader) as $p)
                $stack[] = array($level + 1, $p);

            // Store seen entities to avoid cycles
            $seen[$cur->id] = true;
        }

        // Nothing found
        return 0;
    }

    /**
     * Return a list of all parent elements of this element
     * @param $loader callable A loader that can be used to load additional instances
     * @return array An array of all parent elements
     */
    public function getParents($loader = null)
    {
        $parents = array();
        $ids = array_keys($this->parents);
        foreach ($ids as $id)
        {
            if ($this->parents[$id] === null)
            {
                if (!static::hasInstance($id) && $loader !== null)
                    $loader($id);

                $this->parents[$id] = static::getInstance($id);
            }
            $parents[] = $this->parents[$id];
        }
        return $parents;
    }

    /**
     * Set the parent or parents of this element
     * @param $parents mixed One or more parente elements
     * @throws Wedeto\ACL\Exception When invalid types of parents are specified
     */
    public function setParents($parents)
    {
        $parents = (array)$parents;
        $ownclass = get_class($this);
        $is_root = ($this->id === static::$root);

        $this->parents = array();
        foreach ($parents as $parent)
        {
            if (is_object($parent) && get_class($parent) == $ownclass)
                $this->parents[$parent->id] = $parent;
            elseif (is_scalar($parent))
                $this->parents[$parent] = null;
            else
                throw new Exception("Parent-ID must be a " . $ownclass . " object or a scalar");
        }

        if (empty($this->parents) && !$is_root)
            $this->parents = array(static::getRoot());
    }

    /**
     * @return Hierarchy Returns the root element of the hierarchy
     */
    public static function getRoot()
    {
        return static::getInstance(static::$root);
    }

    /**
     * Get an hierarchy element by specifying its ID
     */
    public static function getInstance($element_id)
    {
        $ownclass = get_called_class();
        if (is_object($element_id) && get_class($element_id) === $ownclass)
            return $element_id;
        if (!is_scalar($element_id))
            throw new Exception("Element-ID must be a scalar");

        if (!isset(self::$database[$ownclass][$element_id]))
        {
            if ($element_id === static::$root)
                self::$database[$ownclass][static::$root] = new $ownclass(static::$root);
            else
                throw new Exception("Element-ID {$element_id} is unknown for {$ownclass}");
        }

        return self::$database[$ownclass][$element_id];
    }

    public static function hasInstance($element_id)
    {
        $ownclass = get_called_class();
        return isset(self::$database[$ownclass][$element_id]);
    }

    /**
     * Clear the cache of elements
     */
    public static function clearCache()
    {
        self::$database[get_called_class()] = array();
    }
}
