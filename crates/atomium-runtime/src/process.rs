use std::time::Duration;

pub fn process_group_alive(pgid: i64) -> bool {
    if pgid <= 0 {
        return false;
    }
    let rc = unsafe { libc::kill(-(pgid as libc::pid_t), 0) };
    if rc == 0 {
        return true;
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    errno != libc::ESRCH
}

pub fn kill_orphaned_process_group_sync(pgid: i64) {
    if pgid <= 0 {
        return;
    }
    let neg_pgid = -(pgid as libc::pid_t);
    unsafe {
        libc::kill(neg_pgid, libc::SIGTERM);
    }
    let term_deadline = std::time::Instant::now() + Duration::from_millis(200);
    while process_group_alive(pgid) && std::time::Instant::now() < term_deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if process_group_alive(pgid) {
        unsafe {
            libc::kill(neg_pgid, libc::SIGKILL);
        }
        let kill_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while process_group_alive(pgid) && std::time::Instant::now() < kill_deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

pub async fn terminate_child_process_group(child: &mut tokio::process::Child, pgid: Option<i64>) {
    if let Some(pgid) = pgid {
        let neg_pgid = -(pgid as libc::pid_t);
        unsafe {
            libc::kill(neg_pgid, libc::SIGTERM);
        }
        let _ = tokio::time::timeout(Duration::from_millis(300), child.wait()).await;

        // Even if the group leader exited on SIGTERM, descendants may ignore SIGTERM and survive.
        // Force-kill the entire process group and verify no members remain before returning.
        if process_group_alive(pgid) {
            unsafe {
                libc::kill(neg_pgid, libc::SIGKILL);
            }
            let _ = child.kill().await;
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while process_group_alive(pgid) && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    } else {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}
