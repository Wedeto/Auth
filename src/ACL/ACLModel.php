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

use Wedeto\DB\Model;
use Wedeto\Util\DI\DI;
use Wedeot\HTTP\Request;

abstract class ACLModel extends Model
{
    /** The ACL that manages all rules and policies */
    protected $_acl = null;

    /** The ACL entity that maps rules to this object */
    protected $_acl_entity = null;

    /**
     * Initialize the ACL object properties
     */
	protected function init()
	{
        parent::init();
        $this->initACL();
	}

    /**
     * Override to provide a list of parent objects where this object can 
     * inherit permissions from. Used by the ACL permission system.
     */
    protected function getParents()
    {
        return [];
    }

    /**
     * @return Wedeto\Auth\ACL\ACL the ACL instance that maps classes and objects.
     */
    public function getACL()
    {
        if (null === $this->_acl)
        {
            $this->_acl = DI::getInjector()->getInstance(ACL::class);
        }

        return $this->_acl;
    }

    /**
     * Return the ACL Entity that manages permissions on this object
     *
     * @return Wedeto\ACL\Entity The ACL Entity that manages permissions
     */
    public function getACLEntity()
    {
        return $this->_acl_entity;
    }
    
    /**
     * Check if an action is allowed on this object. If the ACL subsystem
     * is not loaded, true will be returned.
     *
     * @param $action scalar The action to be performed
     * @param $role Wedeto\ACL\Role The role that wants to perform an action. 
     *                           If not specified, the current user is used.
     * @return boolean True if the action is allowed, false if it is not
     * @throws Wedeto\ACL\Exception When the role or the action is invalid
     */
    public function isAllowed($action, $role = null)
    {
        if ($this->_acl_entity === null)
        {
            return $this->getACL()->getDefaultPolicy(); 
        }
    
        if ($role === null)
        {
            $role = $this->getACL()->getCurrentRole();
        }
    
        return $this->_acl_entity->isAllowed($role, $action, array(get_class($this), "loadByACLID"));
    }
    
    /**
     * Generate a ACL Class name for the called DAO class. It will be composed
     * of the first part of the namespace and the classname by default, but
     * subclasses may override this to alter this behaviour. It should
     * return a unique name
     * 
     * @return string The ACL class name for this DAO
     */
    public static function getACLClass()
    {
        $cl = static::class;
        $parts = explode("\\", $cl);
    
        if (count($parts) === 1)
            return $parts[0];
    
        $first = reset($parts);
        $last = end($parts);
    
        return $first . "_" . $last;
    }
    
    /**
     * Set up the ACL entity. This is called after the init() method,
     * so that ID and parents can be set up before calling.
     */
    protected function initACL()
    {
        // We cannot generate ACL's for object without a ID
        if ($this->id === null)
            return;
        
        // Generate the ACL ID
        $id = $this->generateID($this);
        $acl = $this->getACL();
    
        // Retrieve or obtain the appropriate ACL
        if (!($acl->hasInstance($id)))
            $this->_acl_entity = $acl->createEntity($id, $this->getParents(), $this);
        else
            $this->_acl_entity = $acl->getInstance($id);
    }

    /**
     * Generate a ID based on the provided Model object
     */
    public function generateID()
    {
        $id = $this->getID();
        $fmt_string = "%08s";
        if (is_array($id))
            $id = implode("-", $id);

        if (empty($id))
            throw new Exception("Cannot generate an ID for an empty object");

        $id = substr(sha1($id), 0, 10);
        $acl_class = $this->getACLClass();

        return $acl_class . "#" . $id;
    }
}
