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

use Wedeto\Util\Functions as WF;
use Wedeto\Util\DI\DI;

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

    /** Subclasses should define the name of the root element here */
    protected static $root;

    /** The ACL manager instance */
    protected $_acl = null;

    /**
     * Construction requires the ACL manager
     *
     * @param ACL $acl The ACL to register with
     */
    public function __construct(ACL $acl)
    {
        $this->_acl = $acl;
    }

    /**
     * @return scalar The ID of the Hierarchy element
     */
    public function getID()
    {
        return $this->id;
    }

    /**
     * @return ACL the ACL instance used by this object.
     */
    public function getACL()
    {
        return $this->_acl;
    }

    /**
     * Override the ACL instance used.
     *
     * @param ACL $acl The ACL instance to use
     * @return $this Provides fluent interface
     */
    public function setACL(ACL $acl = null)
    {
        $this->_acl = $acl;
        return $this;
    }

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
     *
     * @param $element Hierarchy The element to check
     * @param $loader LoaderInterface A loader instance that can be used to load additional instances
     * @return boolean True when the current Entity is an ancestor of $element, false otherwise
     */
    public function isAncestorOf(Hierarchy $element, LoaderInterface $loader = null)
    {
        return $loader !== null ? $element->isOffspringOf($this, $loader) : $element->isOffspringOf($this);
    }

    /**
     * Check if the current element is offspring of the specified element
     *
     * @param $role Hierarchy The element to check
     * @param $loader LoaderInterface A loader that can be used to load additional instances
     * @return integer The number of generation levels between the $this and $element - 0 if they're not related
     */
    public function isOffspringOf(Hierarchy $element, LoaderInterface $loader = null)
    {
        if (get_class($element) !== get_class($this))
            return 0;

        $stack = [];
        $parents = $this->getParents($loader);
        foreach ($parents as $p)
            $stack[] = [1, $p];

        $seen = [];
        $level = 0;
        while (!empty($stack))
        {
            list($level, $cur) = array_shift($stack);

            // Avoid infinite cycles
            if (isset($seen[$cur->id]))
                continue;

            // If the ancestor is the requested element, we found our answer
            if ($cur->id === $element->id)
                return $level;

            // Add all parents of this element to the stack
            $parents = $loader === null ? $cur->getParents() : $cur->getParents($loader);
            foreach ($cur->getParents($loader) as $p)
                $stack[] = [$level + 1, $p];

            // Store seen entities to avoid cycles
            $seen[$cur->id] = true;
        }

        // Nothing found
        return 0;
    }

    /**
     * Return a list of all parent elements of this element
     *
     * @param $loader LoaderInterface A loader that can be used to load additional instances
     * @return array An array of all parent elements
     */
    public function getParents(LoaderInterface $loader = null)
    {
        if (empty($this->parents) && $this->id !== static::$root)
            $this->parents = [$this->getRoot()];

        $acl = $this->getACL();
        if (null === $acl)
            throw new \RuntimeException("ACL is null on " . get_class($this));
        $parents = [];
        $ids = array_keys($this->parents);
        foreach ($ids as $id)
        {
            if ($this->parents[$id] === null)
            {
                if (!$acl->hasInstance(static::class, $id) && $loader !== null)
                {
                    $parent = $loader->load($id, static::class);
                    $acl->setInstance($parent);
                    $this->parents[$id] = $parent;
                }
                else
                {
                    $this->parents[$id] = $acl->getInstance(static::class, $id);
                }
            }
            $parents[] = $this->parents[$id];
        }
        return $parents;
    }

    /**
     * Set the parent or parents of this element
     *
     * @param $parents array One or more parent elements. The values can be instances of the same
     *                       class or scalars referring to these instances.
     * @Return $this Provides fluent interface
     * @throws Wedeto\ACL\Exception When invalid types of parents are specified
     */
    public function setParents(array $parents)
    {
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
            $this->parents = [$this->getRoot()];

        return $this;
    }

    /**
     * @return Hierarchy Returns the root element of the hierarchy
     */
    public function getRoot()
    {
        return $this->getACL()->getInstance(static::class, static::$root);
    }

    /**
     * @return the identifier of the root object
     */
    public static function getRootName()
    {
        return static::$root;
    }
}
