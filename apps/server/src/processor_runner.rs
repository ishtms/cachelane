use std::{env, fmt, fs::OpenOptions, io::Write, path::Path, process::Stdio, time::Duration};

use serde_json::Value;
use tokio::{io::AsyncReadExt, process::Command};

const PROCESSOR_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const PROCESSOR_STDERR_BYTES: usize = 64 * 1024;
const PROCESSOR_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const WALL_TIMEOUT: Duration = Duration::from_secs(150);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub(crate) enum ProcessorOperation {
    IndexPdb,
    IndexExe,
    IndexDll,
    GenerateSymcache,
    ProcessCrash,
}

impl ProcessorOperation {
    const fn argument(self) -> &'static str {
        match self {
            Self::IndexPdb => "index-pdb",
            Self::IndexExe => "index-exe",
            Self::IndexDll => "index-dll",
            Self::GenerateSymcache => "generate-symcache",
            Self::ProcessCrash => "process-crash",
        }
    }
}

#[derive(Clone)]
pub(crate) struct ProcessorRunner {
    image_id: String,
    scope: String,
}

pub(crate) struct OwnedContainer {
    pub(crate) name: String,
    pub(crate) job_id: Option<String>,
    pub(crate) lease_token: Option<String>,
}

pub(crate) struct ProcessorOutput {
    pub(crate) stdout: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunnerError {
    Unavailable,
    InvalidImage,
    Rejected,
    ResourceLimit,
    InvalidOutput,
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "container runtime is unavailable",
            Self::InvalidImage => "processor image is invalid",
            Self::Rejected => "processor rejected the input",
            Self::ResourceLimit => "processor resource limit was reached",
            Self::InvalidOutput => "processor output is invalid",
        })
    }
}

impl ProcessorRunner {
    pub(crate) async fn from_environment(scope: &str) -> Result<Self, RunnerError> {
        if !valid_scope(scope) {
            return Err(RunnerError::InvalidImage);
        }
        let image = env::var("FAULTLANE_PROCESSOR_IMAGE")
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or(RunnerError::InvalidImage)?;
        let output = timed_output(
            Command::new("docker")
                .args(["image", "inspect", &image])
                .stdin(Stdio::null()),
            DOCKER_TIMEOUT,
        )
        .await?;
        if !output.status.success() {
            return Err(RunnerError::InvalidImage);
        }
        let images: Vec<Value> =
            serde_json::from_slice(&output.stdout).map_err(|_| RunnerError::InvalidImage)?;
        let image_id = validate_image(&images)?;
        Ok(Self {
            image_id,
            scope: scope.to_owned(),
        })
    }

    #[cfg(test)]
    pub(crate) fn test() -> Self {
        Self {
            image_id: format!("sha256:{}", "a".repeat(64)),
            scope: "b".repeat(64),
        }
    }

    pub(crate) async fn run(
        &self,
        operation: ProcessorOperation,
        input: &Path,
        container_name: &str,
        job_id: &str,
        lease_token: &str,
        copied_output: Option<&Path>,
    ) -> Result<ProcessorOutput, RunnerError> {
        let input = std::fs::canonicalize(input).map_err(|_| RunnerError::Unavailable)?;
        let metadata = std::fs::symlink_metadata(&input).map_err(|_| RunnerError::Unavailable)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(RunnerError::Unavailable);
        }
        let mount = format!(
            "type=bind,src={},dst=/input,readonly",
            docker_mount_source(&input)?
        );
        let arguments = create_arguments(
            container_name,
            &mount,
            &self.image_id,
            &self.scope,
            job_id,
            lease_token,
        );
        let created = timed_output(
            Command::new("docker").args(&arguments).stdin(Stdio::null()),
            DOCKER_TIMEOUT,
        )
        .await;
        let created = match created {
            Ok(output) => output,
            Err(error) => {
                remove_container(container_name).await;
                return Err(error);
            }
        };
        if !created.status.success() {
            remove_container(container_name).await;
            return Err(RunnerError::Unavailable);
        }

        let result = self.execute(container_name, operation).await;
        let result = match result {
            Ok(output) => {
                if let Some(destination) = copied_output {
                    self.copy_output(container_name, destination)
                        .await
                        .map(|()| output)
                } else {
                    Ok(output)
                }
            }
            Err(error) => Err(error),
        };
        remove_container(container_name).await;
        result
    }

    pub(crate) async fn cancel(&self, container_name: &str) {
        remove_container(container_name).await;
    }

    pub(crate) async fn cancel_owned(&self, container_name: &str) -> Result<(), RunnerError> {
        let output = timed_output(
            Command::new("docker")
                .args(["rm", "--force", container_name])
                .stdin(Stdio::null()),
            DOCKER_TIMEOUT,
        )
        .await?;
        if output.status.success() {
            return Ok(());
        }
        let name_filter = format!("name=^{container_name}$");
        let remaining = timed_output(
            Command::new("docker")
                .args([
                    "ps",
                    "--all",
                    "--filter",
                    &name_filter,
                    "--format",
                    "{{.Names}}",
                ])
                .stdin(Stdio::null()),
            DOCKER_TIMEOUT,
        )
        .await?;
        if !remaining.status.success() {
            return Err(RunnerError::Unavailable);
        }
        let names =
            std::str::from_utf8(&remaining.stdout).map_err(|_| RunnerError::InvalidOutput)?;
        if names.lines().any(|name| name == container_name) {
            Err(RunnerError::Unavailable)
        } else {
            Ok(())
        }
    }

    pub(crate) async fn owned_containers(&self) -> Result<Vec<OwnedContainer>, RunnerError> {
        let scope_filter = format!("label=com.faultlane.scope={}", self.scope);
        let output = timed_output(
            Command::new("docker")
                .args([
                    "ps",
                    "--all",
                    "--filter",
                    "label=com.faultlane.processor=true",
                    "--filter",
                    &scope_filter,
                    "--format",
                    "{{.Names}}",
                ])
                .stdin(Stdio::null()),
            DOCKER_TIMEOUT,
        )
        .await?;
        if !output.status.success() {
            return Err(RunnerError::Unavailable);
        }
        let names = std::str::from_utf8(&output.stdout).map_err(|_| RunnerError::InvalidOutput)?;
        let mut containers = Vec::new();
        for name in names.lines().filter(|name| !name.is_empty()) {
            if !valid_container_name(name) {
                return Err(RunnerError::InvalidOutput);
            }
            let inspected = timed_output(
                Command::new("docker")
                    .args(["inspect", name])
                    .stdin(Stdio::null()),
                DOCKER_TIMEOUT,
            )
            .await?;
            if !inspected.status.success() {
                continue;
            }
            let values: Vec<Value> = serde_json::from_slice(&inspected.stdout)
                .map_err(|_| RunnerError::InvalidOutput)?;
            let labels = values
                .first()
                .and_then(|value| value.pointer("/Config/Labels"))
                .and_then(Value::as_object)
                .ok_or(RunnerError::InvalidOutput)?;
            let job_id = labels
                .get("com.faultlane.job-id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let lease_token = labels
                .get("com.faultlane.lease-token")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            containers.push(OwnedContainer {
                name: name.to_owned(),
                job_id,
                lease_token,
            });
        }
        Ok(containers)
    }

    async fn execute(
        &self,
        container_name: &str,
        operation: ProcessorOperation,
    ) -> Result<ProcessorOutput, RunnerError> {
        let started = timed_output(
            Command::new("docker")
                .args(["start", container_name])
                .stdin(Stdio::null()),
            DOCKER_TIMEOUT,
        )
        .await?;
        if !started.status.success() {
            return Err(RunnerError::Unavailable);
        }
        run_bounded(
            Command::new("docker").args([
                "exec",
                container_name,
                "/usr/local/bin/faultlane",
                "processor",
                operation.argument(),
            ]),
            PROCESSOR_OUTPUT_BYTES,
            WALL_TIMEOUT,
        )
        .await
    }

    async fn copy_output(
        &self,
        container_name: &str,
        destination: &Path,
    ) -> Result<(), RunnerError> {
        let output = run_bounded(
            Command::new("docker").args([
                "exec",
                container_name,
                "/bin/cat",
                "/scratch/artifact.symcache",
            ]),
            PROCESSOR_ARTIFACT_BYTES,
            DOCKER_TIMEOUT,
        )
        .await?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|_| RunnerError::InvalidOutput)?;
        file.write_all(&output.stdout)
            .and_then(|()| file.sync_all())
            .map_err(|_| RunnerError::InvalidOutput)
    }
}

fn validate_image(images: &[Value]) -> Result<String, RunnerError> {
    let image = images.first().ok_or(RunnerError::InvalidImage)?;
    let image_id = image
        .get("Id")
        .and_then(Value::as_str)
        .filter(|value| immutable_image_id(value))
        .ok_or(RunnerError::InvalidImage)?;
    let environment = image
        .pointer("/Config/Env")
        .and_then(Value::as_array)
        .ok_or(RunnerError::InvalidImage)?;
    let [path] = environment.as_slice() else {
        return Err(RunnerError::InvalidImage);
    };
    if path
        .as_str()
        .and_then(|value| value.strip_prefix("PATH="))
        .is_none_or(|value| value.is_empty() || value.contains(['\0', '\r', '\n']))
    {
        return Err(RunnerError::InvalidImage);
    }
    Ok(image_id.to_owned())
}

async fn run_bounded(
    command: &mut Command,
    maximum_stdout: usize,
    timeout: Duration,
) -> Result<ProcessorOutput, RunnerError> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| RunnerError::Unavailable)?;
    let stdout = child.stdout.take().ok_or(RunnerError::Unavailable)?;
    let stderr = child.stderr.take().ok_or(RunnerError::Unavailable)?;
    let stdout_task = tokio::spawn(read_bounded(stdout, maximum_stdout));
    let stderr_task = tokio::spawn(read_bounded(stderr, PROCESSOR_STDERR_BYTES));
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => return Err(RunnerError::Unavailable),
        Err(_) => {
            let _ = child.kill().await;
            return Err(RunnerError::ResourceLimit);
        }
    };
    let stdout = stdout_task
        .await
        .map_err(|_| RunnerError::InvalidOutput)??;
    stderr_task
        .await
        .map_err(|_| RunnerError::InvalidOutput)??;
    if !status.success() {
        return match status.code() {
            Some(137 | 143 | 152) | None => Err(RunnerError::ResourceLimit),
            Some(_) => Err(RunnerError::Rejected),
        };
    }
    Ok(ProcessorOutput { stdout })
}

fn create_arguments(
    container_name: &str,
    mount: &str,
    image_id: &str,
    scope: &str,
    job_id: &str,
    lease_token: &str,
) -> Vec<String> {
    let scope_label = format!("com.faultlane.scope={scope}");
    let job_label = format!("com.faultlane.job-id={job_id}");
    let lease_label = format!("com.faultlane.lease-token={lease_token}");
    [
        "create".to_owned(),
        "--name".to_owned(),
        container_name.to_owned(),
        "--label".to_owned(),
        "com.faultlane.processor=true".to_owned(),
        "--label".to_owned(),
        scope_label,
        "--label".to_owned(),
        job_label,
        "--label".to_owned(),
        lease_label,
        "--network".to_owned(),
        "none".to_owned(),
        "--read-only".to_owned(),
        "--mount".to_owned(),
        mount.to_owned(),
        "--tmpfs".to_owned(),
        "/scratch:rw,noexec,nosuid,nodev,size=67108864,mode=0700,uid=65532,gid=65532".to_owned(),
        "--user".to_owned(),
        "65532:65532".to_owned(),
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
        "--security-opt".to_owned(),
        "no-new-privileges".to_owned(),
        "--cpus".to_owned(),
        "1".to_owned(),
        "--memory".to_owned(),
        "2147483648".to_owned(),
        "--memory-swap".to_owned(),
        "2147483648".to_owned(),
        "--pids-limit".to_owned(),
        "64".to_owned(),
        "--ulimit".to_owned(),
        "nofile=256:256".to_owned(),
        "--ulimit".to_owned(),
        "cpu=120:120".to_owned(),
        "--entrypoint".to_owned(),
        "/bin/sleep".to_owned(),
        image_id.to_owned(),
        "infinity".to_owned(),
    ]
    .into_iter()
    .collect()
}

async fn read_bounded(
    reader: impl tokio::io::AsyncRead + Unpin,
    maximum: usize,
) -> Result<Vec<u8>, RunnerError> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(maximum).map_err(|_| RunnerError::InvalidOutput)? + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| RunnerError::InvalidOutput)?;
    if bytes.len() > maximum {
        return Err(RunnerError::ResourceLimit);
    }
    Ok(bytes)
}

async fn timed_output(
    command: &mut Command,
    timeout: Duration,
) -> Result<std::process::Output, RunnerError> {
    command.kill_on_drop(true);
    tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| RunnerError::Unavailable)?
        .map_err(|_| RunnerError::Unavailable)
}

async fn remove_container(container_name: &str) {
    let _ = timed_output(
        Command::new("docker")
            .args(["rm", "--force", container_name])
            .stdin(Stdio::null()),
        DOCKER_TIMEOUT,
    )
    .await;
}

fn immutable_image_id(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_scope(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_container_name(value: &str) -> bool {
    value.len() == 75
        && value.starts_with("faultlane-")
        && value[10..42].bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.as_bytes()[42] == b'-'
        && value[43..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn docker_mount_source(path: &Path) -> Result<String, RunnerError> {
    let value = path.to_str().ok_or(RunnerError::Unavailable)?;
    let value = if let Some(value) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{value}")
    } else {
        value.strip_prefix(r"\\?\").unwrap_or(value).to_owned()
    };
    if value.contains([',', '\r', '\n']) {
        return Err(RunnerError::Unavailable);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::json;
    use tokio::io::AsyncWriteExt;

    use super::{
        RunnerError, create_arguments, docker_mount_source, immutable_image_id, read_bounded,
        valid_container_name, validate_image,
    };

    #[test]
    fn processor_arguments_enforce_the_boundary() {
        let arguments = create_arguments(
            "faultlane-test",
            "type=bind,src=C:\\attempt,dst=/input,readonly",
            &format!("sha256:{}", "a".repeat(64)),
            &"b".repeat(64),
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
        );
        let joined = arguments.join(" ");
        for required in [
            "--network none",
            "--read-only",
            "dst=/input,readonly",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--cpus 1",
            "--memory 2147483648",
            "--memory-swap 2147483648",
            "--pids-limit 64",
            "nofile=256:256",
            "cpu=120:120",
            "/scratch:rw,noexec,nosuid,nodev,size=67108864,mode=0700,uid=65532,gid=65532",
            "--user 65532:65532",
            "com.faultlane.scope=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "com.faultlane.job-id=6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "com.faultlane.lease-token=6ba7b811-9dad-11d1-80b4-00c04fd430c8",
            "/bin/sleep",
            "infinity",
        ] {
            assert!(joined.contains(required), "missing {required}");
        }
        assert!(!joined.contains("--env"));
    }

    #[test]
    fn only_content_addressed_images_are_accepted() {
        assert!(immutable_image_id(&format!("sha256:{}", "a".repeat(64))));
        assert!(!immutable_image_id("faultlane-processor:latest"));
    }

    #[test]
    fn owned_container_names_match_internal_identifiers() {
        let name = format!("faultlane-{}-{}", "a".repeat(32), "b".repeat(32));
        assert!(valid_container_name(&name));
        assert!(!valid_container_name("faultlane-untrusted"));
    }

    #[test]
    fn processor_images_cannot_declare_credentials() {
        let id = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            validate_image(&[json!({"Id": id, "Config": {"Env": ["PATH=/usr/bin"]}})]),
            Ok(id.clone())
        );
        assert_eq!(
            validate_image(&[json!({"Id": id, "Config": {"Env": [
                "PATH=/usr/bin", "AWS_SECRET_ACCESS_KEY=secret"
            ]}})]),
            Err(RunnerError::InvalidImage)
        );
    }

    #[tokio::test]
    async fn processor_streams_stop_at_the_compiled_limit() {
        let (mut writer, reader) = tokio::io::duplex(16);
        let writing = tokio::spawn(async move {
            let _ = writer.write_all(&[0_u8; 6]).await;
        });
        assert_eq!(
            read_bounded(reader, 4).await,
            Err(RunnerError::ResourceLimit)
        );
        let _ = writing.await;
    }

    #[test]
    fn windows_verbatim_paths_are_normalized_for_docker() {
        assert_eq!(
            docker_mount_source(Path::new(r"\\?\C:\faultlane\attempt")),
            Ok(r"C:\faultlane\attempt".to_owned())
        );
        assert!(docker_mount_source(Path::new("C:\\bad,path")).is_err());
    }
}
