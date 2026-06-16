//! In-container exec + tar upload/parse helpers (split from file.rs).
use super::*;

/// Run `sh -c '<script>' sh "<arg>"` inside the container via the daemon exec
/// API. `arg` becomes `$1` (a separate argv entry — no shell injection). Returns
/// (exit_code, stdout, stderr-ish combined). No `docker` CLI required.
pub(crate) async fn ctn_exec_collect(
    container: &str,
    script: &str,
    arg: &str,
) -> Result<(i64, String)> {
    use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
    use futures::StreamExt;

    let dkr = crate::infra::docker::dkr()?;
    let exec = dkr
        .create_exec(
            container,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    script.to_string(),
                    "sh".to_string(),
                    arg.to_string(),
                ]),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow!("容器内执行失败：{e}"))?;
    let started = dkr
        .start_exec(
            &exec.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await
        .map_err(|e| anyhow!("容器内执行失败：{e}"))?;

    let mut buf = String::new();
    if let StartExecResults::Attached { mut output, .. } = started {
        while let Some(item) = output.next().await {
            if let Ok(msg) = item {
                buf.push_str(&String::from_utf8_lossy(&msg.into_bytes()));
            }
        }
    }
    // Inspect for the real exit code.
    let code = dkr
        .inspect_exec(&exec.id)
        .await
        .ok()
        .and_then(|i| i.exit_code)
        .unwrap_or(0);
    Ok((code, buf))
}

/// Run a container script expecting a zero exit (mkdir/delete).
pub(crate) async fn ctn_exec_ok(container: &str, script: &str, arg: &str) -> Result<()> {
    check_abs(arg)?;
    let (code, out) = ctn_exec_collect(container, script, arg).await?;
    if code == 0 {
        Ok(())
    } else {
        let msg = out.trim();
        Err(anyhow!(if msg.is_empty() {
            "操作失败".to_string()
        } else {
            msg.chars().take(300).collect::<String>()
        }))
    }
}

/// Upload a host temp file into the container at `dest_path` using the archive
/// (tar) API, **streaming** the tar body (header + file content read in chunks +
/// padding + footer) so we never hold the whole file in memory. Works even on
/// shell-less images.
pub(crate) async fn ctn_upload_file(
    container: &str,
    temp_path: &Path,
    dest_path: &str,
) -> Result<()> {
    check_abs(dest_path)?;
    let dest = Path::new(dest_path);
    let parent = dest
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/".to_string());
    let fname = dest
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .ok_or_else(|| anyhow!("目标路径无效"))?;

    // File size (for the tar header) from metadata — no full read.
    let size = tokio::fs::metadata(temp_path).await?.len();

    // Build the 512-byte tar header up front (size is known).
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::file());
    header
        .set_path(&fname)
        .map_err(|e| anyhow!("打包失败：{e}"))?;
    header.set_cksum();

    let body = upload_tar_stream(header, temp_path.to_path_buf(), size);

    let dkr = crate::infra::docker::dkr()?;
    let opts = bollard::container::UploadToContainerOptions {
        path: parent,
        ..Default::default()
    };
    dkr.upload_to_container_streaming(container, Some(opts), body)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

/// Build a streaming tar body for a single file: 512-byte header, then the file
/// content read in CHUNK pieces, then NUL padding to a 512 boundary, then the
/// two zero blocks that terminate a tar. Never buffers the whole file.
pub(crate) fn upload_tar_stream(
    header: tar::Header,
    temp_path: std::path::PathBuf,
    size: u64,
) -> impl futures::Stream<Item = bytes::Bytes> + Send + 'static {
    use bytes::Bytes;

    // Tar stages emitted in order.
    enum Stage {
        Header,
        Body { file: tokio::fs::File, left: u64 },
        Pad,
        Footer,
        Done,
    }

    let header_bytes = Bytes::copy_from_slice(header.as_bytes());
    let pad = ((512 - (size % 512)) % 512) as usize;

    futures::stream::unfold(Stage::Header, move |stage| {
        let header_bytes = header_bytes.clone();
        let temp_path = temp_path.clone();
        async move {
            use tokio::io::AsyncReadExt;
            match stage {
                Stage::Header => {
                    // Open the file lazily for the body stage.
                    let next = if size > 0 {
                        match tokio::fs::File::open(&temp_path).await {
                            Ok(file) => Stage::Body { file, left: size },
                            // On open failure, end the stream early (upload fails
                            // server-side with a truncated/invalid tar).
                            Err(_) => Stage::Done,
                        }
                    } else if pad > 0 {
                        Stage::Pad
                    } else {
                        Stage::Footer
                    };
                    Some((header_bytes, next))
                }
                Stage::Body { mut file, left } => {
                    let want = (left as usize).min(CHUNK);
                    let mut buf = vec![0u8; want];
                    match file.read(&mut buf).await {
                        Ok(0) => {
                            // Premature EOF: the file is shorter than the size we
                            // declared in the tar header. Stop WITHOUT emitting
                            // padding/footer so the archive ends mid-entry — the
                            // daemon's tar reader then fails with UnexpectedEOF
                            // and the upload errors, instead of silently writing
                            // a truncated file reported as success.
                            Some((Bytes::new(), Stage::Done))
                        }
                        Ok(n) => {
                            buf.truncate(n);
                            let remaining = left - n as u64;
                            let next = if remaining > 0 {
                                Stage::Body {
                                    file,
                                    left: remaining,
                                }
                            } else if pad > 0 {
                                Stage::Pad
                            } else {
                                Stage::Footer
                            };
                            Some((Bytes::from(buf), next))
                        }
                        // Read error mid-file: same fail-closed handling — end the
                        // archive incomplete so the daemon rejects the upload.
                        Err(_) => Some((Bytes::new(), Stage::Done)),
                    }
                }
                Stage::Pad => Some((Bytes::from(vec![0u8; pad]), Stage::Footer)),
                // Tar archives end with two 512-byte zero blocks.
                Stage::Footer => Some((Bytes::from(vec![0u8; 1024]), Stage::Done)),
                Stage::Done => None,
            }
        }
    })
}

/// Parse a POSIX/GNU tar header: file base name (bytes 0..100, NUL-terminated)
/// and content size (octal ASCII, bytes 124..136). Returns None if the entry
/// isn't a regular file or the header is malformed.
pub(crate) fn parse_tar_header(h: &[u8]) -> Option<(String, u64)> {
    if h.len() < 512 {
        return None;
    }
    // Type flag at offset 156: '0' or '\0' == regular file.
    let typeflag = h[156];
    if !(typeflag == b'0' || typeflag == 0) {
        return None;
    }
    // Name (may be empty if using a GNU long-name extension, which docker
    // doesn't emit for a single file copy).
    let name_end = h[0..100].iter().position(|&b| b == 0).unwrap_or(100);
    let raw_name = String::from_utf8_lossy(&h[0..name_end]).to_string();
    let base = raw_name
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("download")
        .to_string();
    // Size: octal ASCII in bytes 124..136.
    let size_field = &h[124..136];
    let size_str = String::from_utf8_lossy(size_field);
    let size = u64::from_str_radix(size_str.trim().trim_end_matches('\0').trim(), 8).ok()?;
    Some((base, size))
}

/// Map a bollard archive error to a friendly message.
pub(crate) fn friendly_archive_err(e: &bollard::errors::Error) -> String {
    let s = e.to_string();
    if s.contains("no such file") || s.contains("not found") || s.contains("404") {
        "文件不存在".to_string()
    } else {
        s.chars().take(300).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    async fn collect(stream: impl futures::Stream<Item = bytes::Bytes>) -> Vec<u8> {
        let mut buf = Vec::new();
        futures::pin_mut!(stream);
        while let Some(chunk) = stream.next().await {
            buf.extend_from_slice(&chunk);
        }
        buf
    }

    fn header_for(size: u64) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_size(size);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::file());
        h.set_path("f.bin").unwrap();
        h.set_cksum();
        h
    }

    #[tokio::test]
    async fn upload_stream_is_well_formed_when_complete() {
        let p = std::env::temp_dir().join(format!("dn7-ctnup-ok-{}", std::process::id()));
        std::fs::write(&p, b"hello world").unwrap();
        let size = std::fs::metadata(&p).unwrap().len();
        let out = collect(upload_tar_stream(header_for(size), p.clone(), size)).await;
        // header (512) + content padded to 512 + 1024-byte footer.
        assert_eq!(out.len(), 512 + 512 + 1024);
        // A valid tar ends in at least two zero blocks.
        assert!(out[out.len() - 1024..].iter().all(|&b| b == 0));
        let _ = std::fs::remove_file(&p);
    }

    #[tokio::test]
    async fn upload_stream_omits_footer_when_file_truncated() {
        // Declare a larger size than the file actually has → the body read hits
        // EOF early and the stream must end WITHOUT the terminating zero blocks,
        // so the daemon's tar reader rejects the upload instead of writing a
        // silently-truncated file.
        let p = std::env::temp_dir().join(format!("dn7-ctnup-trunc-{}", std::process::id()));
        std::fs::write(&p, b"short").unwrap();
        let declared = 9999u64; // far bigger than the 5-byte file
        let out = collect(upload_tar_stream(header_for(declared), p.clone(), declared)).await;
        // Must NOT carry a full 1024-byte zero footer (archive is intentionally
        // incomplete). It's header + partial body, well under header+declared.
        assert!(out.len() < 512 + declared as usize);
        let tail_ok = out.len() >= 1024 && out[out.len() - 1024..].iter().all(|&b| b == 0);
        assert!(
            !tail_ok,
            "truncated upload must not emit a complete tar footer"
        );
        let _ = std::fs::remove_file(&p);
    }
}
