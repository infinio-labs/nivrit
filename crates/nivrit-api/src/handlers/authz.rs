use nivrit_core::{NivritError, Result, Role};
use nivrit_db::{
    models::{OrgMembershipRow, ProjectMemberRow},
    pool::DbPool,
    queries,
};
use uuid::Uuid;

/// Verify that `user_id` is a member of `org_id` and return the membership row.
pub async fn require_org_member(
    db: &DbPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<OrgMembershipRow> {
    queries::get_org_member(db, org_id, user_id).await
}

/// Verify that `user_id` is a member of `project_id` and return the membership row.
pub async fn require_project_member(
    db: &DbPool,
    project_id: Uuid,
    user_id: Uuid,
) -> Result<ProjectMemberRow> {
    queries::get_project_member(db, project_id, user_id).await
}

/// Return `Ok(role)` if the member's role is at least `required`, otherwise `Forbidden`.
pub fn require_role(membership: &ProjectMemberRow, required: Role) -> Result<Role> {
    require_role_str(&membership.role, required)
}

/// The role gate for an environment-scoped action (secret CRUD, folders,
/// imports, tags -- ADR 0009). An `environment_memberships` row for this
/// user overrides their project-level role for this specific environment;
/// absent one, the project-level role applies exactly as it did before this
/// table existed, so a project that's never used environment-level grants
/// sees no behavior change.
///
/// Still requires project membership even when an override exists: the
/// override is a role *substitution* for someone already on the project, not
/// a side door around project membership. A user who somehow has an
/// environment-membership row but was removed from the project is rejected
/// by the `require_project_member` fallback below only when *no* override
/// row is found -- callers granting overrides are responsible for not
/// leaving orphaned rows behind after removing someone from a project (no
/// "remove project member" endpoint exists yet to test this against; noted
/// as a sharp edge for whenever one is added).
pub async fn require_environment_role(
    db: &DbPool,
    project_id: Uuid,
    environment_id: Uuid,
    user_id: Uuid,
    required: Role,
) -> Result<Role> {
    if let Some(env_membership) =
        queries::get_environment_member(db, environment_id, user_id).await?
    {
        return require_role_str(&env_membership.role, required);
    }
    let membership = require_project_member(db, project_id, user_id).await?;
    require_role(&membership, required)
}

/// Return `Ok(role)` if the org member's role is at least `required`, otherwise
/// `Forbidden`.
///
/// Org membership alone is not a privilege grant: a user lands in an org's
/// membership table as a Viewer merely by being invited to *one project*
/// inside it (see `invite_member` in `handlers::projects`), with no org owner
/// ever deciding they should be trusted with the org itself. Any handler that
/// lets an org member take an org-wide action (creating a project, inviting
/// another org member, ...) must gate on this, not just on `require_org_member`
/// succeeding.
pub fn require_org_role(membership: &OrgMembershipRow, required: Role) -> Result<Role> {
    require_role_str(&membership.role, required)
}

fn require_role_str(role: &str, required: Role) -> Result<Role> {
    let role = role_from_str(role)?;
    if role_rank(role) >= role_rank(required) {
        Ok(role)
    } else {
        Err(NivritError::Forbidden)
    }
}

fn role_from_str(s: &str) -> Result<Role> {
    match s {
        "admin" => Ok(Role::Admin),
        "member" => Ok(Role::Member),
        "viewer" => Ok(Role::Viewer),
        "none" => Ok(Role::None),
        _ => Err(NivritError::Internal(format!("invalid role in db: {s}"))),
    }
}

fn role_rank(role: Role) -> u8 {
    match role {
        Role::None => 0,
        Role::Viewer => 1,
        Role::Member => 2,
        Role::Admin => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn membership_with_role(role: &str) -> ProjectMemberRow {
        ProjectMemberRow {
            user_id: Uuid::nil(),
            project_id: Uuid::nil(),
            role: role.into(),
            encrypted_project_key: vec![],
            project_key_nonce: vec![],
            project_key_algorithm: "aes256gcm-v1".into(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn admin_passes_all_roles() {
        let m = membership_with_role("admin");
        assert_eq!(require_role(&m, Role::Admin).unwrap(), Role::Admin);
        assert_eq!(require_role(&m, Role::Member).unwrap(), Role::Admin);
        assert_eq!(require_role(&m, Role::Viewer).unwrap(), Role::Admin);
    }

    #[test]
    fn member_passes_member_and_viewer() {
        let m = membership_with_role("member");
        assert!(require_role(&m, Role::Admin).is_err());
        assert_eq!(require_role(&m, Role::Member).unwrap(), Role::Member);
        assert_eq!(require_role(&m, Role::Viewer).unwrap(), Role::Member);
    }

    #[test]
    fn viewer_only_passes_viewer() {
        let m = membership_with_role("viewer");
        assert!(require_role(&m, Role::Admin).is_err());
        assert!(require_role(&m, Role::Member).is_err());
        assert_eq!(require_role(&m, Role::Viewer).unwrap(), Role::Viewer);
    }

    /// `none` is rank 0 -- it must fail even the lowest real gate (`Viewer`),
    /// which is the entire point of it existing: without a tier below
    /// `Viewer`, an environment override could never actually deny access,
    /// only ever grant more of it.
    #[test]
    fn none_role_fails_every_gate_including_viewer() {
        let m = membership_with_role("none");
        assert!(require_role(&m, Role::Viewer).is_err());
        assert!(require_role(&m, Role::Member).is_err());
        assert!(require_role(&m, Role::Admin).is_err());
    }

    #[test]
    fn invalid_db_role_errors() {
        let m = membership_with_role("owner");
        assert!(require_role(&m, Role::Viewer).is_err());
    }

    fn org_membership_with_role(role: &str) -> OrgMembershipRow {
        OrgMembershipRow {
            id: Uuid::nil(),
            org_id: Uuid::nil(),
            user_id: Uuid::nil(),
            role: role.into(),
            created_at: Utc::now(),
        }
    }

    /// An org Viewer only got there by being invited to one project, not by an
    /// org owner's decision - so it must not clear a Member-level gate like
    /// `create_project`'s.
    #[test]
    fn org_viewer_cannot_clear_member_gate() {
        let m = org_membership_with_role("viewer");
        assert!(require_org_role(&m, Role::Member).is_err());
        assert_eq!(require_org_role(&m, Role::Viewer).unwrap(), Role::Viewer);
    }

    #[test]
    fn org_member_and_admin_clear_member_gate() {
        assert_eq!(
            require_org_role(&org_membership_with_role("member"), Role::Member).unwrap(),
            Role::Member
        );
        assert_eq!(
            require_org_role(&org_membership_with_role("admin"), Role::Member).unwrap(),
            Role::Admin
        );
    }
}
