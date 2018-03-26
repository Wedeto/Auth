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

use Wedeto\DB\DAO;

/**
 * An Entity is any object or class of objects that rules can be applied to.
 *
 * Every entity has one or more parent class. At the top of the hierarchy there
 * is the 'Everything' class, which is the ancestor of all entities.
 */
class Entity extends Hierarchy
{
    /** Define the name of the root element */
    protected static $root = "EVERYTHING";

    /** Define the name of the Entity */
    protected $name = null;

    /** The rules applying to this Entity */
    protected $rules = null;

    /**
     * Create a new Entity
     *
     * @param ACL $acl The ACL to register this entity with
     * @param $entity_id scalar The ID of the entity to construct
     * @param $parent_id mixed The (list of) ID's or Entity objects that are parents
     */
    public function __construct(ACL $acl, $entity_id, array $parent_id = [])
    {
        parent::__construct($acl);

        $own_class = get_class($this);
        if (!is_scalar($entity_id))
            throw new Exception("Entity-ID must be a scalar");

        if ($acl->hasInstance($own_class, $entity_id))
            throw new Exception("Duplicate entity: $entity_id");

        $this->id = $entity_id;
        $this->setParents($parent_id);
        $acl->setInstance($this);
    }

    /**
     * Get a definitive answer to the question:
     *
     * Is X allowed by Y on Z?
     *
     * It will obtain the policy based on the rules on this Entity and parent
     * Entities applying to this Role and parent Roles.  If no applicable
     * policy is found, the default policy, as configured in Rule, is returned.
     *
     * @param $role Role The role that wants to take action
     * @param $action string The action to be performed
     * @param $loader LoaderInterface A loader to load additional entities
     * @return boolean True when the action is allowed, false otherwise
     */
    public function isAllowed(Role $role, string $action, LoaderInterface $loader = null)
    {
        $policy = $this->getPolicy($role, $action, $loader);
        if ($policy === Rule::UNDEFINED)
            $policy = $this->getACL()->getDefaultPolicy();

        return $policy === Rule::ALLOW;
    }

    /**
     * Find the policy to the Role performing the action on this Entity.
     *
     * @param $role Role The Role wanting to perform an action
     * @param $action string The action Role wishes to perform
     * @param $loader callable A method that can be used to load additional instances
     * @return integer The policy, either Rule::ALLOW or Rule::DENY.
     */
    public function getPolicy(Role $role, string $action, LoaderInterface $loader = null)
    {
        $rules = $this->getRules();
        $pref_policy = $this->getACL()->getPreferredPolicy();

        $inherit = true;
        $ancestor_distance = null;
        $ancestor_policy = null;
        foreach ($rules as $rule)
        {
            // NOINHERIT-rules disable rule inheritance and do nothing else
            if ($rule->policy === Rule::NOINHERIT)
            {
                $inherit = false;
                continue;
            }

            // Always ignore INHERIT rules
            if ($rule->policy === Rule::INHERIT)
                continue;

            // If the action doesn't match, don't consider the rule
            // TODO: What about container actions?
            if ($rule->action !== $action)
                continue;

            // If the Rule applies to the specified Role, its answer is definitive
            if ($rule->role->is($role))
                return $rule->policy;

            // Find the closest matching parent
            if (($distance = $rule->role->isAncestorOf($role, $loader)) > 0)
            {
                // Always select the closest parent that has a defined rule.
                // When there are several conflicting rules, applying to the
                // same level of ancestry, select the preferred policy.
                if (
                    $ancestor_distance === null || 
                    $distance < $ancestor_distance || 
                    ($distance === $ancestor_distance && $rule->policy === $pref_policy)
                )
                {
                    $ancestor_policy = $rule;
                    $ancestor_distance = $distance;
                }
            }
        }

        if ($ancestor_policy !== null)
            return $ancestor_policy->policy;

        // This Entity doesn't have a defined policy for this action.
        // If inheritance is disabled, or the Entity does not have a parent (root),
        // return the default policy.
        if (!$inherit || empty($this->parents))
        {
            // Return default policy
            return Rule::UNDEFINED;
        }

        // Inherit from the parents
        $parents = $this->getParents($loader);
        $policy = Rule::UNDEFINED;
        foreach ($parents as $parent)
        {
            $policy = $parent->getPolicy($role, $action, $loader);
            // If an Entity has multiple parents, just one of them needs to
            // allow the action to allow it on this Entity.
            if ($policy === $pref_policy)
                return $pref_policy;
        }

        // None of the parents have a preferred policy, so return the alternative
        return $policy;
    }

    /**
     * @return array A list of all rules for this Entity.
     */
    public function getRules()
    {
        if ($this->rules === null)
            $this->rules = $this->getACL()->loadRules($this->id);

        return $this->rules;
    }

    /**
     * Unload the rules. Mainly useful for testing
     *
     * @return $this Provides fluent interface
     */
    public function resetRules()
    {
        $this->rules = null;
        return $this;
    }
}
