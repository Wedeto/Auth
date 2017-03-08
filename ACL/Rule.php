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

namespace WASP\Auth\ACL;

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

    /** The default policy when no policy applies */
    protected static $default_policy = Rule::DENY;

    /** Which policy has preference when you conflicting Rule's exist */
    protected static $preferred_policy = Rule::ALLOW;

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

    /** Used to validate actions */
    protected static $action_validator = null;

    /**
     * Create the object providing entity, role, action and policy.
     *
     * @param $entity_id scalar|Entity The Entity this rule applies to
     * @param $role_id scalar|Role The Role this rule applies to
     * @param $action scalar The action on the Entity this rule has a policy on
     * @param $policy integer One of Rule::UNDEFINED, Rule::ALLOW or Rule::DENY
     * @throws WASP\ACL\Exception When one of the setters throws an exception
     */
    public function __construct($entity_id, $role_id, $action, $policy)
    {
        $this->setEntity($entity);
        $this->setRole($role);
        $this->setPolicy($policy);
        $this->setAction($action);
        $this->changed = false;
    }

    /**
     * Set the role this Rule applies to. 
     *
     * @param $role_id scalar|Role Either a Role object or a Role-ID
     * @throws WASP\ACL\Exception When the role is not a Role object or a scalar
     */
    public function setRole($role_id)
    {
        if (!empty($role_id) && $this->policy === Rule::NOINHERIT)
            throw new Exception("Cannot set a role for a NOINHERIT rule");

        if ($role_id instanceof Role)
        {
            $this->role = $role_id;
            $role_id = $role_id->getRoleID();
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
     * @throws WASP\ACL\Exception When the entity is not a Entity object or a scalar
     */
    public function setEntity($entity_id)
    {
        if ($entity_id instanceof Entity)
        {
            $this->entity = $entity_id;
            $entity_id = $entity_id->getEntityID();
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
            $this->entity = new Entity($this->entity_id);
        return $this->entity;
    }

    /**
     * @return the Role object associated to this Rule
     */
    public function getRole()
    {
        if ($this->role === null)
            $this->role = new Role($this->role_id);
        return $this->role;
    }

    /**
     * Set the policy on the entity
     * @param policy integer Should be one of Rule::ALLOW, Rule::DENY or Rule::UNDEFINED
     * @throws WASP\ACL\Exception When the Rule is not ALLOW, DENY or UNDEFINED
     */
    public function setPolicy($policy)
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
     * @throws WASP\ACL\Exception When the action is not a scalar
     */
    public function setAction($action)
    {
        if (!is_scalar($action))
            throw new Exception("Action must be a scalar");
        if (!empty($action) && $this->policy === Rule::NOINHERIT)
            throw new Exception("Cannot set an action for a NOINHERIT rule");

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
     * @throws WASP\ACL\Exception When the field does not exist
     */
    public function __get($field)
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
     */
    public function setRecord($record)
    {
        $this->record = $record;
    }

    /**
     * Set the action validator used to validate actions on rules.
     */
    public static function setActionValidator(IActionValidator $validator)
    {
        self::$action_validator = $validator;
    }

    /**
     * Set the default policy which is applied when no rule
     * specifies a definitive answer.
     * @param $policy scalar Either one of (Rule::ALLOW, Rule::DENY) or one
     *                       of the strings "ALLOW" or "DENY"
     * @throws Exception When an invalid policy is returned
     */
    public static function setDefaultPolicy($policy)
    {
        if (is_string($policy))
        {
            $policy = trim(strtoupper($policy));
            if ($policy === "ALLOW")
                $policy = Rule::ALLOW;
            elseif ($policy === "DENY")
                $policy = Rule::DENY;
        }

        if (!($policy === Rule::ALLOW || $policy === Rule::DENY))
            throw new Exception("Default policy should be either Rule::ALOW or Rule::DENY"); 

        self::$default_policy = $policy;
    }

    /**
     * @return integer The default policy, the policy to apply when no explicity policy is defined
     */
    public static function getDefaultPolicy()
    {
        return self::$default_policy;
    }

    /**
     * Set the default policy which is applied when no rule
     * specifies a definitive answer.
     * @param $policy scalar Either one of (Rule::ALLOW, Rule::DENY) or one
     *                       of the strings "ALLOW" or "DENY"
     * @throws Exception When an invalid policy is returned
     */
    public static function setPreferredPolicy($policy)
    {
        if (is_string($policy))
        {
            $policy = trim(strtoupper($policy));
            if ($policy === "ALLOW")
                $policy = Rule::ALLOW;
            elseif ($policy === "DENY")
                $policy = Rule::DENY;
        }

        if (!($policy === Rule::ALLOW || $policy === Rule::DENY))
            throw new Exception("Default policy should be either Rule::ALOW or Rule::DENY"); 

        self::$preferred_policy = $policy;
    }

    /**
     * @return integer The preferred policy, the policy to select when several policies are defined.
     */
    public static function getPreferredPolicy()
    {
        return self::$preferred_policy;
    }
}
