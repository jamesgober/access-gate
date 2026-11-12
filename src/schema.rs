//! The service's vocabulary, compiled once at boot.

use alloc::{boxed::Box, string::String, vec::Vec};

use crate::{
    error::SchemaError,
    perm::{MAX_PERMISSIONS, Perm, PermSet},
    subject::{AttrId, MAX_ATTRIBUTES},
};

/// The most roles one schema can declare.
pub const MAX_ROLES: usize = 1024;

/// The longest name a permission, role, or attribute can have, in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// FNV-1a, 64-bit.
struct Fnv(u64);

impl Fnv {
    const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= u64::from(*b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }

    fn name(&mut self, name: &str) {
        self.bytes(&(name.len() as u32).to_le_bytes());
        self.bytes(name.as_bytes());
    }

    fn section(&mut self, id: u8, count: usize) {
        self.bytes(&u32::MAX.to_le_bytes());
        self.bytes(&[id]);
        self.bytes(&(count as u32).to_le_bytes());
    }

    const fn finish(&self) -> u64 {
        self.0
    }
}

/// A role, by its position in the compiled [`Schema`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RoleId(u16);

impl RoleId {
    /// The position of the role in the schema.
    #[must_use]
    pub const fn index(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone)]
struct RoleDecl {
    name: String,
    grants: Vec<String>,
    inherits: Vec<String>,
}

/// Declares a [`Schema`]. Start one with [`Schema::builder`].
///
/// Mistakes are kept until [`build`](Self::build), which reports the first
/// one, so a chain of calls reads top to bottom without `?` on every line.
#[derive(Debug, Clone)]
#[must_use = "a builder does nothing until `build` is called"]
pub struct SchemaBuilder {
    service: String,
    perms: Vec<String>,
    roles: Vec<RoleDecl>,
    attrs: Vec<String>,
    guests: Vec<String>,
    error: Option<SchemaError>,
}

impl SchemaBuilder {
    fn fail(&mut self, error: SchemaError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// Declare permissions. Each becomes one bit, in the order given.
    pub fn permissions(mut self, names: &[&str]) -> Self {
        for name in names {
            self.perms.push(String::from(*name));
        }
        self
    }

    /// Declare one permission.
    pub fn permission(mut self, name: &str) -> Self {
        self.perms.push(String::from(name));
        self
    }

    /// Declare a role that grants `grants` (permission names).
    pub fn role(mut self, name: &str, grants: &[&str]) -> Self {
        self.roles.push(RoleDecl {
            name: String::from(name),
            grants: grants.iter().map(|g| String::from(*g)).collect(),
            inherits: Vec::new(),
        });
        self
    }

    /// Make the role declared last also hold everything `parent` holds.
    /// Can be called more than once; inheritance is resolved at
    /// [`build`](Self::build), so the parent may be declared later.
    pub fn inherits(mut self, parent: &str) -> Self {
        match self.roles.last_mut() {
            Some(role) => role.inherits.push(String::from(parent)),
            None => self.fail(SchemaError::InheritsWithoutRole),
        }
        self
    }

    /// Permissions every visitor holds, signed in or not (reading public
    /// posts). Signed-in subjects hold them too.
    pub fn guest_grants(mut self, perms: &[&str]) -> Self {
        self.guests.extend(perms.iter().map(|p| String::from(*p)));
        self
    }

    /// Declare an attribute that rules may compare (for example `org_id`).
    pub fn attribute(mut self, name: &str) -> Self {
        self.attrs.push(String::from(name));
        self
    }

    /// Compile the schema.
    ///
    /// # Errors
    ///
    /// The first mistake found: an invalid or duplicate name, too many
    /// permissions, roles, or attributes, a role granting a permission that
    /// was not declared, inheriting from a role that does not exist, or a
    /// cycle in inheritance. A service refuses to boot on any of them.
    pub fn build(self) -> Result<Schema, SchemaError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        check_name(&self.service)?;
        if self.perms.len() > MAX_PERMISSIONS {
            return Err(SchemaError::TooManyPermissions);
        }
        if self.roles.len() > MAX_ROLES {
            return Err(SchemaError::TooManyRoles);
        }
        if self.attrs.len() > MAX_ATTRIBUTES {
            return Err(SchemaError::TooManyAttributes);
        }
        check_unique(&self.perms)?;
        check_unique(&self.attrs)?;
        let role_names: Vec<String> = self.roles.iter().map(|r| r.name.clone()).collect();
        check_unique(&role_names)?;

        let perms: Vec<Box<str>> = self.perms.into_iter().map(String::into_boxed_str).collect();
        let find_perm = |name: &str| perms.iter().position(|p| &**p == name);
        let find_role = |name: &str| role_names.iter().position(|r| r == name);

        // Direct grants and parent links, by index.
        let mut direct = Vec::with_capacity(self.roles.len());
        let mut parents: Vec<Vec<usize>> = Vec::with_capacity(self.roles.len());
        for role in &self.roles {
            let mut set = PermSet::new();
            for grant in &role.grants {
                let index = find_perm(grant).ok_or_else(|| SchemaError::UnknownPermission {
                    name: grant.clone().into_boxed_str(),
                })?;
                set.insert(Perm::from_index(index as u8));
            }
            direct.push(set);
            let mut links = Vec::with_capacity(role.inherits.len());
            for parent in &role.inherits {
                let index = find_role(parent).ok_or_else(|| SchemaError::UnknownRole {
                    name: parent.clone().into_boxed_str(),
                })?;
                links.push(index);
            }
            parents.push(links);
        }

        // Resolve inheritance depth first; a role met again while it is
        // still being resolved is a cycle.
        let count = direct.len();
        let mut state = alloc::vec![Visit::New; count];
        let mut resolved = alloc::vec![PermSet::new(); count];
        for start in 0..count {
            resolve(
                start,
                &direct,
                &parents,
                &mut state,
                &mut resolved,
                &role_names,
            )?;
        }

        let mut guests = PermSet::new();
        for g in &self.guests {
            let index = find_perm(g).ok_or_else(|| SchemaError::UnknownPermission {
                name: g.clone().into_boxed_str(),
            })?;
            guests.insert(Perm::from_index(index as u8));
        }
        let roles = role_names
            .into_iter()
            .zip(resolved)
            .map(|(name, set)| (name.into_boxed_str(), set))
            .collect();
        Ok(Schema {
            service: self.service.into_boxed_str(),
            perms,
            roles,
            attrs: self.attrs.into_iter().map(String::into_boxed_str).collect(),
            guests,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Visit {
    New,
    Open,
    Done,
}

fn resolve(
    start: usize,
    direct: &[PermSet],
    parents: &[Vec<usize>],
    state: &mut [Visit],
    resolved: &mut [PermSet],
    names: &[String],
) -> Result<(), SchemaError> {
    // Iterative depth-first walk so a deep chain cannot overflow the stack.
    let mut stack: Vec<(usize, usize)> = Vec::new();
    if state[start] == Visit::Done {
        return Ok(());
    }
    state[start] = Visit::Open;
    stack.push((start, 0));
    while let Some(&(node, next)) = stack.last() {
        if let Some(&parent) = parents[node].get(next) {
            if let Some(top) = stack.last_mut() {
                top.1 += 1;
            }
            match state[parent] {
                Visit::Done => {}
                Visit::Open => {
                    return Err(SchemaError::RoleCycle {
                        role: names[parent].clone().into_boxed_str(),
                    });
                }
                Visit::New => {
                    state[parent] = Visit::Open;
                    stack.push((parent, 0));
                }
            }
        } else {
            let mut set = direct[node];
            for &parent in &parents[node] {
                set = set.union(resolved[parent]);
            }
            resolved[node] = set;
            state[node] = Visit::Done;
            stack.pop();
        }
    }
    Ok(())
}

fn check_name(name: &str) -> Result<(), SchemaError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-:".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(SchemaError::InvalidName {
            name: String::from(name).into_boxed_str(),
        })
    }
}

fn check_unique(names: &[String]) -> Result<(), SchemaError> {
    for (i, name) in names.iter().enumerate() {
        check_name(name)?;
        if names[..i].contains(name) {
            return Err(SchemaError::Duplicate {
                name: name.clone().into_boxed_str(),
            });
        }
    }
    Ok(())
}

/// A service's permissions, roles, and attributes, compiled at boot.
///
/// Permissions become bit numbers, roles become [`PermSet`]s with
/// inheritance already resolved, and attributes become [`AttrId`]s. Nothing
/// here changes after [`build`](SchemaBuilder::build); a hot reload builds a
/// new schema and swaps it whole.
///
/// ```
/// use access_gate::Schema;
///
/// let schema = Schema::builder("web")
///     .permissions(&["post.read", "post.write", "post.publish"])
///     .role("member", &["post.read"])
///     .role("author", &["post.write"]).inherits("member")
///     .role("editor", &["post.publish"]).inherits("author")
///     .build()?;
///
/// let editor = schema.grants(["editor"]);
/// assert!(editor.covers(&schema.perms(&["post.read", "post.publish"])?));
/// # Ok::<(), access_gate::SchemaError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Schema {
    service: Box<str>,
    perms: Vec<Box<str>>,
    roles: Vec<(Box<str>, PermSet)>,
    attrs: Vec<Box<str>>,
    guests: PermSet,
}

impl Schema {
    /// Start declaring the schema of `service`.
    pub fn builder(service: &str) -> SchemaBuilder {
        SchemaBuilder {
            service: String::from(service),
            perms: Vec::new(),
            roles: Vec::new(),
            attrs: Vec::new(),
            guests: Vec::new(),
            error: None,
        }
    }

    /// The service this schema belongs to.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// A 64-bit fingerprint of everything a stored permission set or
    /// attribute set depends on: the service name, the permission and
    /// attribute names in declaration order, what each role grants (with
    /// inheritance resolved), and the guest grants. Store it next to a
    /// [`PermSet`] kept outside the process (a session record), and refuse
    /// the set when the fingerprint differs: a reordered or inserted
    /// permission changes every bit after it, and a role that lost a
    /// permission must not keep it in old sessions.
    ///
    /// ```
    /// use access_gate::Schema;
    ///
    /// let a = Schema::builder("web").permissions(&["post.read", "admin.delete"]).build()?;
    /// let b = Schema::builder("web").permissions(&["admin.delete", "post.read"]).build()?;
    /// assert_ne!(a.fingerprint(), b.fingerprint());
    /// # Ok::<(), access_gate::SchemaError>(())
    /// ```
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        // FNV-1a: stable across builds and platforms, no dependency. Not a
        // security boundary by itself (the schema is the service's own
        // code), only a version check. A name goes in as its length then
        // its bytes; a section opens with a length no name can have
        // (u32::MAX), its id, and its item count, so no name can imitate a
        // section boundary.
        let mut f = Fnv::new();
        f.section(0, 1);
        f.name(&self.service);
        f.section(1, self.perms.len());
        for p in &self.perms {
            f.name(p);
        }
        f.section(2, self.attrs.len());
        for a in &self.attrs {
            f.name(a);
        }
        f.section(3, self.roles.len());
        for (name, set) in &self.roles {
            f.name(name);
            f.bytes(&set.to_bytes());
        }
        f.section(4, 1);
        f.bytes(&self.guests.to_bytes());
        f.finish()
    }

    /// The permission called `name`.
    #[must_use]
    pub fn perm(&self, name: &str) -> Option<Perm> {
        self.perms
            .iter()
            .position(|p| &**p == name)
            .map(|i| Perm::from_index(i as u8))
    }

    /// The set of the permissions named.
    ///
    /// # Errors
    ///
    /// [`SchemaError::UnknownPermission`] for a name the schema does not
    /// declare, so a route referring to it refuses the boot.
    pub fn perms(&self, names: &[&str]) -> Result<PermSet, SchemaError> {
        let mut set = PermSet::new();
        for name in names {
            let perm = self
                .perm(name)
                .ok_or_else(|| SchemaError::UnknownPermission {
                    name: String::from(*name).into_boxed_str(),
                })?;
            set.insert(perm);
        }
        Ok(set)
    }

    /// The name of `perm`.
    #[must_use]
    pub fn perm_name(&self, perm: Perm) -> Option<&str> {
        self.perms.get(usize::from(perm.index())).map(|p| &**p)
    }

    /// The role called `name`.
    #[must_use]
    pub fn role(&self, name: &str) -> Option<RoleId> {
        self.roles
            .iter()
            .position(|(n, _)| &**n == name)
            .map(|i| RoleId(i as u16))
    }

    /// Everything `role` holds, inheritance included.
    #[must_use]
    pub fn role_perms(&self, role: RoleId) -> PermSet {
        self.roles
            .get(usize::from(role.0))
            .map_or(PermSet::EMPTY, |(_, set)| *set)
    }

    /// Everything the named roles hold together: what a session gets at
    /// login. A name the schema does not know grants nothing (a role removed
    /// from the schema but still stored on an account fails closed).
    #[must_use]
    pub fn grants<I, S>(&self, role_names: I) -> PermSet
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        role_names
            .into_iter()
            .filter_map(|name| self.role(name.as_ref()))
            .fold(PermSet::new(), |acc, role| acc.union(self.role_perms(role)))
    }

    /// What every visitor holds ([`SchemaBuilder::guest_grants`]); pass it
    /// to [`authorize_with`](crate::authorize_with).
    #[must_use]
    pub const fn guests(&self) -> &PermSet {
        &self.guests
    }

    /// The attribute called `name`.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<AttrId> {
        self.attrs
            .iter()
            .position(|a| &**a == name)
            .map(|i| AttrId::new_bounded(i as u8))
    }

    /// The name of `attr`.
    #[must_use]
    pub fn attribute_name(&self, attr: AttrId) -> Option<&str> {
        self.attrs.get(usize::from(attr.index())).map(|a| &**a)
    }

    /// Every attribute, in declaration order.
    pub fn attributes(&self) -> impl Iterator<Item = (AttrId, &str)> + '_ {
        self.attrs
            .iter()
            .enumerate()
            .map(|(i, a)| (AttrId::new_bounded(i as u8), &**a))
    }

    /// How many permissions the schema declares.
    #[must_use]
    pub fn permission_count(&self) -> usize {
        self.perms.len()
    }

    /// How many roles the schema declares.
    #[must_use]
    pub fn role_count(&self) -> usize {
        self.roles.len()
    }
}
