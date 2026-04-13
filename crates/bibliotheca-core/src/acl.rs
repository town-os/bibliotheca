use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::identity::{GroupId, UserId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    Read,
    Write,
    List,
    Delete,
    Admin,
}

impl Permission {
    /// Admin implies every other permission.
    pub fn implied_by(self, granted: Permission) -> bool {
        granted == Permission::Admin || granted == self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Principal {
    User(UserId),
    Group(GroupId),
    /// Anonymous access via the opt-in HTTP interface. Never matches
    /// unless the HTTP interface is enabled and the entry is explicitly
    /// listed on the subvolume ACL.
    Public,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub principal: Principal,
    pub permissions: HashSet<Permission>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Acl {
    pub entries: Vec<AclEntry>,
}

impl Acl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Owner-only ACL — used as the default when a subvolume is created
    /// without explicit ACL entries.
    pub fn owner_only(owner: UserId) -> Self {
        let mut perms = HashSet::new();
        perms.insert(Permission::Admin);
        Self {
            entries: vec![AclEntry {
                principal: Principal::User(owner),
                permissions: perms,
            }],
        }
    }

    pub fn grant(&mut self, principal: Principal, permission: Permission) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.principal == principal) {
            entry.permissions.insert(permission);
            return;
        }
        let mut perms = HashSet::new();
        perms.insert(permission);
        self.entries.push(AclEntry {
            principal,
            permissions: perms,
        });
    }

    pub fn revoke(&mut self, principal: &Principal, permission: Permission) {
        if let Some(entry) = self.entries.iter_mut().find(|e| &e.principal == principal) {
            entry.permissions.remove(&permission);
        }
    }

    /// Resolve whether the given user (with the given group memberships)
    /// is granted the requested permission on this ACL.
    pub fn check(
        &self,
        user: Option<UserId>,
        groups: &HashSet<GroupId>,
        wanted: Permission,
        public_allowed: bool,
    ) -> bool {
        for entry in &self.entries {
            let matches = match &entry.principal {
                Principal::User(uid) => Some(*uid) == user,
                Principal::Group(gid) => groups.contains(gid),
                Principal::Public => public_allowed,
            };
            if !matches {
                continue;
            }
            if entry.permissions.iter().any(|p| wanted.implied_by(*p)) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_only_grants_admin() {
        let owner = UserId::new();
        let acl = Acl::owner_only(owner);
        assert!(acl.check(Some(owner), &HashSet::new(), Permission::Read, false));
        assert!(acl.check(Some(owner), &HashSet::new(), Permission::Delete, false));
    }

    #[test]
    fn group_membership_grants_access() {
        let group = GroupId::new();
        let mut acl = Acl::new();
        acl.grant(Principal::Group(group), Permission::Read);

        let mut groups = HashSet::new();
        groups.insert(group);
        assert!(acl.check(Some(UserId::new()), &groups, Permission::Read, false));
        assert!(!acl.check(Some(UserId::new()), &groups, Permission::Write, false));
    }

    #[test]
    fn public_requires_opt_in() {
        let mut acl = Acl::new();
        acl.grant(Principal::Public, Permission::Read);
        // public_allowed=false: HTTP interface disabled
        assert!(!acl.check(None, &HashSet::new(), Permission::Read, false));
        assert!(acl.check(None, &HashSet::new(), Permission::Read, true));
    }
}
