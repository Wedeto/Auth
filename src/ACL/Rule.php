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
 * A Rule encapsulates one policy, relating one Role to one Entity, specifying
 * the policy regarding a certain action.
 *
 * Entities and Roles can be specified by either their scalar ID, or their Entity or Role instances.
 * Rule does not impose any standard on action, although a validator can be assigned.
 * 
 */
class Rule
{
    /** DENY: This rule denies the requested action */
    const DENY = 0;

    /** ALLOW: This rule allows the requested action */
    const ALLOW = 1;

    /** NOINHERIT: This rule disables policy inheritance from parent Entities */
    const NOINHERIT = 2;

    /** INHERIT: Inherit policies from the parent Entity */
    const INHERIT = 3;

    /** UNDEFINED: Used only as a policy result: none of the applicable rules give a definitive answer */
    const UNDEFINED = 4;

    /** READ: Read permission on an entity */
    const READ = "READ";

    /** WRITE: Write permission on an entity */
    const WRITE = "WRITE";

    /** The ID of the entity this rule applies to */
    protected $entity_id;

    /** The Entity object, where instances are cached after instantiation */
    protected $entity = null;

    /** The ID of the Role this rule applies to */
    protected $role_id;

    /** The Role object, where instances are cached after instantation */
    protected $role = null;

    /** The action this rule has a policy on */
    protected $action;

    /** The policy on the requested action on the entity */
    protected $policy;

    /** Whether or not this rule has changed */
    protected $changed;

    /** Reference to external storage, such as database records */
    protected $record;

    /**
     * Create the object providing entity, role, action and policy.
     *
     * @param $entity_id scalar|Entity The Entity this rule applies to
     * @param $role_id scalar|Role The Role this rule applies to
     * @param $action scalar The action on the Entity this rule has a policy on
     * @param $policy integer One of Rule::UNDEFINED, Rule::ALLOW or Rule::DENY
     * @throws Wedeto\ACL\Exception When one of the setters throws an exception
     */
    public function __construct($entity_id, $role_id, string $action, int $policy)
    {
        $this->setEntity($entity_id);
        $this->setRole($role_id);
        $this->setAction($action);
        $this->setPolicy($policy);
        $this->changed = false;
    }

    /**
     * Set the role this Rule applies to. 
     *
     * @param $role_id scalar|Role Either a Role object or a Role-ID
     * @throws Wedeto\ACL\Exception When the role is not a Role object or a scalar
     */
    public function setRole($role_id)
    {
        if (!empty($role_id) && $this->policy === Rule::NOINHERIT)
            throw new Exception("Rule::NOINHERIT can not be used in combination with a role");

        if ($role_id instanceof Role)
        {
            $this->role = $role_id;
            $role_id = $role_id->getID();
        }
        elseif (!is_scalar($role_id))
            throw new Exception("Role-ID must be a Role or a scalar");

        if ($role_id !== $this->role_id)
        {
            $this->changed = true;
            $this->role_id = $role_id;
        }
    }

    /**
     * Set the entity this Rule applies to
     * 
     * @param $entity_id scalar|Entity Either a Entity object or a Role-ID
     * @throws Wedeto\ACL\Exception When the entity is not a Entity object or a scalar
     */
    public function setEntity($entity_id)
    {
        if ($entity_id instanceof Entity)
        {
            $this->entity = $entity_id;
            $entity_id = $entity_id->getID();
        }
        elseif (!is_scalar($entity_id))
            throw new Exception("Entity-ID must be an Entity or a scalar");

        if ($entity_id !== $this->entity_id)
        {
            $this->entity_id = $entity_id;
            $this->changed = true;
        }
    }

    /** 
     * @return the entity object associated to this Rule
     */
    public function getEntity()
    {
        if ($this->entity === null)
            $this->entity = Entity::getInstance($this->entity_id);
        return $this->entity;
    }

    /**
     * @return the Role object associated to this Rule
     */
    public function getRole()
    {
        if ($this->role === null)
            $this->role = Role::getInstance($this->role_id);
        return $this->role;
    }

    /**
     * Set the policy on the entity
     * @param policy integer Should be one of Rule::ALLOW, Rule::DENY or Rule::UNDEFINED
     * @throws Wedeto\ACL\Exception When the Rule is not ALLOW, DENY or UNDEFINED
     */
    public function setPolicy(int $policy)
    {
        if (!($policy === Rule::ALLOW || $policy === Rule::DENY || $policy === Rule::INHERIT || $policy == Rule::NOINHERIT))
            throw new Exception("Policy must be either Rule::ALLOW, Rule::DENY, Rule::INHERIT or Rule::NOINHERIT");

        if ($policy == Rule::NOINHERIT && !empty($this->action))
            throw new Exception("Rule::NOINHERIT can not be used in combination with an action");

        if ($policy == Rule::NOINHERIT && !empty($this->role_id))
            throw new Exception("Rule::NOINHERIT can not be used in combination with a role");

        if ($policy !== $this->policy)
        {
            $this->policy = $policy;
            $this->changed = true;
        }
    }

    /**
     * Set the action on the entity
     * @param $action scalar The action this Rule has a policy on.
     * @throws Wedeto\ACL\Exception When the action is not a scalar
     */
    public function setAction(string $action)
    {
        if (!empty($action) && $this->policy === Rule::NOINHERIT)
            throw new Exception("Rule::NOINHERIT can not be used in combination with an action");

        $action = (string)$action;
        if ($action !== $this->action)
        {
            if (self::$action_validator !== null)
            {
                if (($reason = self::$action_validator->isValid($action)) !== true)
                    throw new Exception("Action can not be validated: " . $reason);
            }
            $this->changed = true;
            $this->action = $action;
        }
    }

    /**
     * Magic getter for all properties of this Rule.
     * @param $field scalar The property to return
     * @return The value for the property
     * @throws Wedeto\ACL\Exception When the field does not exist
     */
    public function __get(string $field)
    {
        if (property_exists($this, $field))
        {
            if ($field === "role")
                return $this->getRole();
            if ($field === "entity")
                return $this->getEntity();
            return $this->$field;
        }
        throw new Exception("Invalid field for Rule: $field");
    }

    /**
     * @return The associated record for this rule
     */
    public function getRecord()
    {
        return $this->record;
    }

    /**
     * Set the record associated to this rule
     * @param $record mixed Data to be associated with this rule
     * @return Rule Provides fluent interface
     */
    public function setRecord($record)
    {
        $this->record = $record;
        return $this;
    }

}
