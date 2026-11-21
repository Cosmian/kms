//! Deployment-profile step of the KMS configuration wizard (decision tree of
//! `installation/high_availability_mode.md`).

use std::io::Write as _;

use dialoguer::{Confirm, Select, theme::ColorfulTheme};

use super::PromptResultExt;
use crate::{
    config::{DatabaseType, RegionRole},
    result::KResult,
};

/// The six deployment profiles of the high-availability guide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeploymentProfile {
    SingleNode,
    CloudLoadBalancer,
    RoundRobinDns,
    KeepalivedOnly,
    HaProxy,
    MultiRegion,
}

impl DeploymentProfile {
    /// Profile number in the guide (1..=6).
    pub(crate) const fn number(self) -> u8 {
        match self {
            Self::SingleNode => 1,
            Self::CloudLoadBalancer => 2,
            Self::RoundRobinDns => 3,
            Self::KeepalivedOnly => 4,
            Self::HaProxy => 5,
            Self::MultiRegion => 6,
        }
    }

    /// Profile title, as in the guide.
    pub(crate) const fn title(self) -> &'static str {
        match self {
            Self::SingleNode => "Single node",
            Self::CloudLoadBalancer => "Cloud load balancer",
            Self::RoundRobinDns => "Round-robin DNS",
            Self::KeepalivedOnly => "Keepalived only",
            Self::HaProxy => "HAProxy, with or without Keepalived",
            Self::MultiRegion => "Multi-region active-active",
        }
    }

    /// `true` when several KMS nodes or regions share the data.
    pub(crate) const fn is_multi_node(self) -> bool {
        !matches!(self, Self::SingleNode)
    }
}

/// Where the nodes of a multi-node deployment run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeLocation {
    CloudLoadBalancer,
    NoLoadBalancer,
    OnPremises,
}

/// Answers to the decision-tree questions; `None` = question not asked on this path.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ProfileAnswers {
    pub confidential_vm: bool,
    pub several_regions: bool,
    pub several_nodes: bool,
    pub location: Option<NodeLocation>,
    pub spread_load: Option<bool>,
}

/// Walk the decision tree of the high-availability guide.
pub(crate) const fn resolve_profile(a: ProfileAnswers) -> DeploymentProfile {
    if a.confidential_vm {
        return DeploymentProfile::SingleNode;
    }
    if a.several_regions {
        return DeploymentProfile::MultiRegion;
    }
    if !a.several_nodes {
        return DeploymentProfile::SingleNode;
    }
    match a.location {
        Some(NodeLocation::CloudLoadBalancer) => DeploymentProfile::CloudLoadBalancer,
        Some(NodeLocation::NoLoadBalancer) => DeploymentProfile::RoundRobinDns,
        Some(NodeLocation::OnPremises) => {
            if matches!(a.spread_load, Some(true)) {
                DeploymentProfile::HaProxy
            } else {
                DeploymentProfile::KeepalivedOnly
            }
        }
        None => DeploymentProfile::SingleNode,
    }
}

/// Databases usable with `profile`, taken from `variants`.
///
/// `SQLite` supports one node only; Redis-Findex multi-node is not supported.
pub(crate) fn allowed_databases(
    profile: DeploymentProfile,
    variants: &[DatabaseType],
) -> Vec<DatabaseType> {
    let keep = |v: &DatabaseType| match profile {
        DeploymentProfile::SingleNode => true,
        DeploymentProfile::MultiRegion => matches!(v, DatabaseType::Postgresql),
        _ => matches!(v, DatabaseType::Postgresql | DatabaseType::Mysql),
    };
    variants.iter().copied().filter(keep).collect()
}

/// Prompt items for the region role of profile 6.
pub(crate) const REGION_ROLE_CHOICES: [&str; 2] = [
    "Leader region (exactly one region of the deployment)",
    "Follower region",
];

/// Maps an index of [`REGION_ROLE_CHOICES`] to the role.
pub(crate) const fn region_role_for_choice(idx: usize) -> RegionRole {
    if idx == 1 {
        RegionRole::Follower
    } else {
        RegionRole::Leader
    }
}

/// Operating notes printed at the end of the wizard for `profile`.
pub(crate) fn profile_notes(
    profile: DeploymentProfile,
    region_role: RegionRole,
) -> Vec<&'static str> {
    let mut notes = Vec::new();
    if profile.is_multi_node() {
        notes.push(
            "Use this same configuration on every node, with the same server certificate, named \
             after the address clients use.",
        );
    }
    match profile {
        DeploymentProfile::CloudLoadBalancer
        | DeploymentProfile::KeepalivedOnly
        | DeploymentProfile::HaProxy => {
            notes.push("Point the health check at GET /health?strict=true on the HTTPS port.");
        }
        DeploymentProfile::RoundRobinDns => notes
            .push("Round-robin DNS has no failover: remove a failed node from the DNS records."),
        DeploymentProfile::MultiRegion => {
            notes.push("Run the wizard once per region; exactly one region is the leader.");
            notes.push("Use the same ceremony_secret in every region.");
            notes.push(
                "Exclude cluster_nodes from the Spock replication set and enable delta-apply on \
                 gcm_invocations.count.",
            );
            if region_role == RegionRole::Follower {
                notes.push(
                    "CRL generation and Crypto Officer ceremonies are rejected on this follower \
                     region; send them to the leader.",
                );
            }
        }
        DeploymentProfile::SingleNode => {}
    }
    notes.push(
        "Profile details: https://docs.cosmian.com/key_management_system/installation/high_availability_mode.html",
    );
    notes
}

/// Ask the decision-tree questions and return the profile and the region role.
pub(crate) fn configure_profile() -> KResult<(DeploymentProfile, RegionRole)> {
    let theme = ColorfulTheme::default();
    let ask = |prompt: &str| -> KResult<bool> {
        Confirm::with_theme(&theme)
            .with_prompt(prompt)
            .default(false)
            .interact()
            .prompt_err()
    };
    let mut answers = ProfileAnswers {
        confidential_vm: ask("Run the KMS in a Cosmian confidential VM?")?,
        ..ProfileAnswers::default()
    };
    if !answers.confidential_vm {
        answers.several_regions =
            ask("Serve clients from several regions (one PostgreSQL database per region)?")?;
        if !answers.several_regions {
            answers.several_nodes = ask("More than one KMS node?")?;
            if answers.several_nodes {
                let idx = Select::with_theme(&theme)
                    .with_prompt("Where do the nodes run?")
                    .items(&[
                        "Cloud, with a managed load balancer",
                        "No load balancer, no failover needed",
                        "On premises",
                    ])
                    .default(0)
                    .interact()
                    .prompt_err()?;
                let location = match idx {
                    0 => NodeLocation::CloudLoadBalancer,
                    1 => NodeLocation::NoLoadBalancer,
                    _ => NodeLocation::OnPremises,
                };
                answers.location = Some(location);
                if location == NodeLocation::OnPremises {
                    answers.spread_load = Some(ask("Spread the load over all nodes?")?);
                }
            }
        }
    }

    let profile = resolve_profile(answers);
    let region_role = if profile == DeploymentProfile::MultiRegion {
        region_role_for_choice(
            Select::with_theme(&theme)
                .with_prompt("Role of this region")
                .items(&REGION_ROLE_CHOICES)
                .default(0)
                .interact()
                .prompt_err()?,
        )
    } else {
        RegionRole::Leader
    };

    writeln!(
        std::io::stdout().lock(),
        "  ℹ  Deployment profile {}: {}",
        profile.number(),
        profile.title()
    )?;
    Ok((profile, region_role))
}
