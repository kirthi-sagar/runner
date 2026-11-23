//! OCI container tier: host runtime probing and v1.0.2 bundle
//! generation. Phase 1 ships discovery + spec emission; execution
//! binds a probed runtime in a later phase.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::mounts::validate_no_home_mount;

/// OCI runtimes in probe order: standalone rootless runtimes first
/// (fast C, reference, Rust-native), then engine CLIs, daemon last.
pub const OCI_RUNTIME_CANDIDATES: [&str; 5] = ["crun", "runc", "youki", "podman", "docker"];

/// True when `path` names a runnable binary: a regular file, on unix
/// with at least one execute bit set.
fn is_runnable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_in_dirs(name: &str, dirs: impl Iterator<Item = PathBuf>) -> Option<PathBuf> {
    dirs.map(|dir| dir.join(name))
        .find(|path| is_runnable(path))
}

/// `which` over an explicit PATH value (pure; unit-tested without
/// touching the process environment).
pub fn find_on_path_with(name: &str, path_var: &str) -> Option<PathBuf> {
    find_in_dirs(name, std::env::split_paths(path_var))
}

/// `which` over the process PATH.
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| find_in_dirs(name, std::env::split_paths(&path)))
}

/// Discover the OCI runtime binary: an explicit config override wins
/// (a missing override fails closed naming the path); otherwise the
/// first runnable candidate on PATH in [`OCI_RUNTIME_CANDIDATES`]
/// order. Absence reports every name searched so `--strict` callers
/// (and humans) get an actionable diagnostic; strict enforcement
/// itself binds at execution time.
pub fn probe_oci_runtime(explicit: Option<&Path>) -> Result<PathBuf, String> {
    probe_oci_runtime_with(explicit, &|name| find_on_path(name))
}

fn probe_oci_runtime_with(
    explicit: Option<&Path>,
    lookup: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return if is_runnable(path) {
            Ok(path.to_path_buf())
        } else {
            Err(format!(
                "configured OCI runtime '{}' is not a runnable binary",
                path.display()
            ))
        };
    }
    for candidate in OCI_RUNTIME_CANDIDATES {
        if let Some(path) = lookup(candidate) {
            return Ok(path);
        }
    }
    Err(format!(
        "no OCI runtime found on PATH (looked for {}); install one or set [sandbox.container] runtime_path",
        OCI_RUNTIME_CANDIDATES.join(", ")
    ))
}

/// OCI runtime-spec version this generator targets.
pub const OCI_SPEC_VERSION: &str = "1.0.2";
/// Job working directory inside the container.
pub const OCI_WORKDIR: &str = "/workspace";

/// Invoker UID/GID for the rootless 1:1 user-namespace mapping.
fn invoker_ids() -> (u32, u32) {
    #[cfg(unix)]
    {
        (
            nix::unistd::Uid::current().as_raw(),
            nix::unistd::Gid::current().as_raw(),
        )
    }
    #[cfg(not(unix))]
    {
        (0, 0)
    }
}

/// OCI `config.json` bundle specification (runtime-spec subset).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciBundleSpec {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub process: OciProcess,
    pub root: OciRoot,
    pub hostname: String,
    pub mounts: Vec<OciMount>,
    pub linux: OciLinux,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciProcess {
    pub user: OciUser,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub terminal: bool,
    #[serde(rename = "noNewPrivileges")]
    pub no_new_privileges: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciUser {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciRoot {
    pub path: String,
    pub readonly: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciMount {
    pub destination: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub mount_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciNamespace {
    #[serde(rename = "type")]
    pub ns_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciIdMapping {
    #[serde(rename = "containerID")]
    pub container_id: u32,
    #[serde(rename = "hostID")]
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciLinuxCpu {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciLinuxMemory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciLinuxResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<OciLinuxCpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<OciLinuxMemory>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciLinux {
    pub namespaces: Vec<OciNamespace>,
    #[serde(rename = "uidMappings", default, skip_serializing_if = "Vec::is_empty")]
    pub uid_mappings: Vec<OciIdMapping>,
    #[serde(rename = "gidMappings", default, skip_serializing_if = "Vec::is_empty")]
    pub gid_mappings: Vec<OciIdMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<OciLinuxResources>,
}

/// Default mounts for a runnable bundle: `/proc`, `/dev`, read-only
/// `/sys`, and the tmpfs job workspace.
fn default_mounts() -> Vec<OciMount> {
    vec![
        OciMount {
            destination: "/proc".to_string(),
            mount_type: Some("proc".to_string()),
            source: Some("proc".to_string()),
            options: vec![],
        },
        OciMount {
            destination: "/dev".to_string(),
            mount_type: Some("tmpfs".to_string()),
            source: Some("tmpfs".to_string()),
            options: ["nosuid", "strictatime", "mode=755"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        },
        OciMount {
            destination: "/sys".to_string(),
            mount_type: Some("sysfs".to_string()),
            source: Some("sysfs".to_string()),
            options: ["nosuid", "noexec", "nodev", "ro"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        },
        OciMount {
            destination: OCI_WORKDIR.to_string(),
            mount_type: Some("tmpfs".to_string()),
            source: Some("tmpfs".to_string()),
            options: ["nosuid", "nodev", "mode=755"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        },
    ]
}

impl OciBundleSpec {
    /// Minimal runnable bundle: entrypoint argv + env, cwd `/workspace`,
    /// rootless userns mapped 1:1 to the invoker, default mounts,
    /// read-only rootfs, no resource limits (see [`with_limits`](Self::with_limits)).
    pub fn new(args: Vec<String>, env: Vec<String>) -> Self {
        let (uid, gid) = invoker_ids();
        Self {
            oci_version: OCI_SPEC_VERSION.to_string(),
            process: OciProcess {
                user: OciUser { uid: 0, gid: 0 },
                args,
                env,
                cwd: OCI_WORKDIR.to_string(),
                terminal: false,
                no_new_privileges: true,
            },
            root: OciRoot {
                path: "rootfs".to_string(),
                readonly: true,
            },
            hostname: "runner-job".to_string(),
            mounts: default_mounts(),
            linux: OciLinux {
                namespaces: ["pid", "network", "mount", "ipc", "uts", "user"]
                    .into_iter()
                    .map(|ns| OciNamespace {
                        ns_type: ns.to_string(),
                    })
                    .collect(),
                uid_mappings: vec![OciIdMapping {
                    container_id: 0,
                    host_id: uid,
                    size: 1,
                }],
                gid_mappings: vec![OciIdMapping {
                    container_id: 0,
                    host_id: gid,
                    size: 1,
                }],
                resources: None,
            },
        }
    }

    /// Extra bind mount (host `source` → container `destination`).
    /// Host sources under `/home` fail closed (existing invariant);
    /// the destination is container-namespaced and must be absolute.
    pub fn with_mount(
        mut self,
        source: &Path,
        destination: &str,
        readonly: bool,
    ) -> Result<Self, String> {
        validate_no_home_mount(&[source])?;
        if !destination.starts_with('/') {
            return Err(format!(
                "container mount destination must be absolute, got '{destination}'"
            ));
        }
        let mut options = vec!["rbind".to_string()];
        if readonly {
            options.push("ro".to_string());
        }
        self.mounts.push(OciMount {
            destination: destination.to_string(),
            mount_type: Some("bind".to_string()),
            source: Some(source.display().to_string()),
            options,
        });
        Ok(self)
    }

    /// cgroup v2 limits: CPU weight (1–10000) + memory max in bytes.
    /// Out-of-range values fail closed rather than emitting an
    /// invalid bundle.
    pub fn with_limits(mut self, cpu_weight: u64, memory_max_bytes: u64) -> Result<Self, String> {
        if !(1..=10000).contains(&cpu_weight) {
            return Err(format!(
                "container cpu weight must be 1-10000, got {cpu_weight}"
            ));
        }
        if memory_max_bytes == 0 || memory_max_bytes > i64::MAX as u64 {
            return Err(format!(
                "container memory max must be 1-{} bytes, got {memory_max_bytes}",
                i64::MAX as u64
            ));
        }
        self.linux.resources = Some(OciLinuxResources {
            cpu: Some(OciLinuxCpu {
                weight: Some(cpu_weight),
            }),
            memory: Some(OciLinuxMemory {
                limit: Some(memory_max_bytes as i64),
            }),
        });
        Ok(self)
    }

    /// Serialize to the bundle `config.json` value.
    pub fn to_json(&self) -> Result<serde_json::Value, String> {
        serde_json::to_value(self).map_err(|e| format!("cannot encode bundle spec: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake runnable binary (executable bit where the platform has one).
    fn fake_runtime(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    fn path_var(dirs: &[PathBuf]) -> String {
        std::env::join_paths(dirs).unwrap().into_string().unwrap()
    }

    #[test]
    fn find_on_path_resolves_runnable_files() {
        let dir = runner_core::test_support::TempDir::new("oci-path").unwrap();
        let runc = fake_runtime(dir.path(), "runc");
        let path_var = path_var(&[dir.path().to_path_buf()]);
        assert_eq!(find_on_path_with("runc", &path_var), Some(runc));
        assert_eq!(find_on_path_with("crun", &path_var), None);
        assert_eq!(find_on_path_with("runc", ""), None);
    }

    #[test]
    fn probe_prefers_candidate_order_over_path_order() {
        let dir = runner_core::test_support::TempDir::new("oci-order").unwrap();
        let early = dir.path().join("early");
        let late = dir.path().join("late");
        std::fs::create_dir_all(&early).unwrap();
        std::fs::create_dir_all(&late).unwrap();
        // docker sits earlier on PATH, but runc outranks it.
        fake_runtime(&early, "docker");
        let runc = fake_runtime(&late, "runc");
        let path_var = path_var(&[early, late]);
        let found =
            probe_oci_runtime_with(None, &|name| find_on_path_with(name, &path_var)).unwrap();
        assert_eq!(found, runc);
    }

    #[test]
    fn probe_honors_explicit_override_or_fails_closed() {
        let dir = runner_core::test_support::TempDir::new("oci-explicit").unwrap();
        let custom = fake_runtime(dir.path(), "my-runtime");
        assert_eq!(
            probe_oci_runtime_with(Some(&custom), &|_| None).unwrap(),
            custom
        );
        let missing = dir.path().join("nope");
        let err = probe_oci_runtime_with(Some(&missing), &|_| None).unwrap_err();
        assert!(err.contains("nope"), "{err}");
        // Non-runnable override (plain data file) fails closed too.
        let data = dir.path().join("data.txt");
        std::fs::write(&data, b"not a binary").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        #[cfg(unix)]
        assert!(probe_oci_runtime_with(Some(&data), &|_| None).is_err());
    }

    #[test]
    fn probe_missing_runtime_names_every_candidate() {
        let err = probe_oci_runtime_with(None, &|_| None).unwrap_err();
        for candidate in OCI_RUNTIME_CANDIDATES {
            assert!(err.contains(candidate), "{err}");
        }
        assert!(err.contains("runtime_path"), "{err}");
    }

    fn spec() -> OciBundleSpec {
        OciBundleSpec::new(
            vec!["/bin/sh".to_string(), "-c".to_string(), "make".to_string()],
            vec!["CI=true".to_string(), "PATH=/usr/bin".to_string()],
        )
        .with_limits(500, 512 * 1024 * 1024)
        .unwrap()
    }

    #[test]
    fn bundle_json_roundtrips_losslessly() {
        let spec = spec();
        let json = spec.to_json().unwrap();
        let back: OciBundleSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn bundle_carries_spec_invariants() {
        let json = spec().to_json().unwrap();
        assert_eq!(json["ociVersion"], "1.0.2");
        assert_eq!(json["process"]["args"][2], "make");
        assert_eq!(json["process"]["env"][0], "CI=true");
        assert_eq!(json["process"]["cwd"], "/workspace");
        assert_eq!(json["root"]["readonly"], true);
        let namespaces: Vec<&str> = json["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ns| ns["type"].as_str().unwrap())
            .collect();
        assert_eq!(
            namespaces,
            vec!["pid", "network", "mount", "ipc", "uts", "user"]
        );
        // Workspace tmpfs mount present.
        let workspace = json["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/workspace")
            .unwrap();
        assert_eq!(workspace["type"], "tmpfs");
        // cgroup v2 limits.
        assert_eq!(json["linux"]["resources"]["cpu"]["weight"], 500);
        assert_eq!(
            json["linux"]["resources"]["memory"]["limit"],
            512 * 1024 * 1024
        );
        // Rootless 1:1 identity mapping anchored at container 0.
        assert_eq!(json["linux"]["uidMappings"][0]["containerID"], 0);
        assert_eq!(json["linux"]["uidMappings"][0]["size"], 1);
    }

    #[test]
    fn bundle_limits_reject_garbage() {
        let base = OciBundleSpec::new(vec!["x".to_string()], vec![]);
        assert!(base.clone().with_limits(0, 1024).is_err());
        assert!(base.clone().with_limits(10001, 1024).is_err());
        assert!(base.clone().with_limits(100, 0).is_err());
        assert!(base.with_limits(100, 1024).is_ok());
    }

    #[test]
    fn bundle_mounts_reject_home_and_relative() {
        let base = OciBundleSpec::new(vec!["x".to_string()], vec![]);
        // Host paths under /home fail closed.
        assert!(base
            .clone()
            .with_mount(Path::new("/home/dev/data"), "/data", true)
            .is_err());
        assert!(base
            .clone()
            .with_mount(Path::new("/home/dev/.ssh"), "/secrets", true)
            .is_err());
        // Container-relative destinations fail closed.
        assert!(base
            .clone()
            .with_mount(Path::new("/opt/data"), "data", true)
            .is_err());
        // Sane bind mounts pass through with options.
        let spec = base
            .with_mount(Path::new("/opt/data"), "/data", true)
            .unwrap();
        let mount = spec
            .mounts
            .iter()
            .find(|m| m.destination == "/data")
            .unwrap();
        assert_eq!(mount.mount_type.as_deref(), Some("bind"));
        assert!(mount.options.contains(&"ro".to_string()));
    }
}
