//! 原子文件写入：同目录 tmp + rename，保留原文件权限。
//!
//! 两个调用方（凭据、统计）都在业务请求等待链之外，但仍要求"要么旧内容、
//! 要么新内容"，不能出现半截文件。这里刻意**不加 fsync**——耐久性维持改动前
//! 的现状，而 fsync 会直接加到首响时间上（计划已裁决）。
//!
//! # 调用方契约
//!
//! tmp 路径由目标路径固定派生（`*.json.tmp`），因此**调用方必须持有互斥锁**
//! 串行化对同一目标的写入。凭据与统计两个调用方都已在 `credentials_save_lock`
//! / 统计锁内调用本函数；新增调用方必须遵守同一契约，否则两个写者会互相踩
//! tmp 文件。
//!
//! # 权限
//!
//! tmp 文件在**创建时**就收紧到 0600（unix），而不是写完再 `set_permissions`：
//! 凭据文件含 refreshToken / clientSecret / 代理密码，先 `File::create` 再收紧
//! 会让这些秘密在窗口期内以 umask 权限（通常 0644）存在于磁盘上，崩溃时还会
//! 残留。原文件的权限在 **rename 之后**才复制到最终路径——rename 之前就把 tmp
//! 放宽回 0644，等于把秘密暴露在"已写好、还没换上去"的窗口里。
//!
//! # 符号链接
//!
//! 目标是符号链接时先解析到真实目标，再在真实目标所在目录做 tmp + rename。
//! 这样成功路径（rename）与失败回退路径（`fs::write`）语义一致——都更新真实
//! 目标、都保留链接本身；否则 rename 会把目录项里的链接替换成普通文件，真实
//! 目标反而永远不更新。

use std::io::Write;
use std::path::{Path, PathBuf};

/// 新建 tmp 文件时的权限：只有属主可读写。
#[cfg(unix)]
const TMP_FILE_MODE: u32 = 0o600;

/// 解析真实写入目标：目标是符号链接时返回它指向的真实路径。
///
/// 成功路径是 rename（替换目录项），失败回退路径是 `fs::write`（跟随链接）。
/// 不先解析的话，两条路径语义相反：rename 会把链接换成一个普通文件，链接
/// 指向的真实目标永远不更新。解析之后两者都写真实目标、都保留链接本身。
///
/// 悬空链接（目标文件不存在）时 `canonicalize` 会失败，此时按 POSIX 语义
/// 把链接的相对目标解析到链接所在目录——写入要么落在链接真正指向的位置，
/// 要么因为该位置不可写而失败，绝不静默把链接替换成普通文件。
fn resolve_write_target(path: &Path) -> PathBuf {
    let is_symlink = std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false);
    if !is_symlink {
        return path.to_path_buf();
    }
    if let Ok(resolved) = std::fs::canonicalize(path) {
        return resolved;
    }
    match std::fs::read_link(path) {
        Ok(link) if link.is_absolute() => link,
        Ok(link) => match path.parent() {
            Some(dir) => dir.join(link),
            None => link,
        },
        Err(_) => path.to_path_buf(),
    }
}

/// 原子写入 `bytes` 到 `path`。
///
/// - tmp 与目标同目录：生产在 Docker 里跑，目录可能是独立挂载卷，
///   用系统临时目录会跨设备 rename 失败（EXDEV），把"偶发写坏"变成"永远写不了"。
/// - tmp 创建即 0600，且**保持** 0600 直到 rename 完成；原文件权限在 rename
///   之后才复制到最终路径（见模块文档的权限一节）。
/// - `path` 是符号链接时写到它指向的真实目标（见 [`resolve_write_target`]）。
/// - rename 失败（如单文件 bind mount 不允许替换目录项）时退回原地写并告警，
///   保证不劣于改动前。
pub fn write_atomically(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let target = resolve_write_target(path);
    let path = target.as_path();
    let tmp_path = path.with_extension("json.tmp");
    let permissions = std::fs::metadata(path).ok().map(|meta| meta.permissions());

    let written = (|| -> std::io::Result<()> {
        // 测试注入点刻意放在闭包内：它模拟的是"tmp 创建这一步失败"，与真实
        // `create_tmp_file` 返回 Err 走完全同一条路径。放在闭包外会让注入绕过
        // 下面的回退分支，测出来的就不是生产路径了。
        #[cfg(test)]
        if let Some(error) = test_faults::fail_tmp_creation() {
            return Err(error);
        }
        let mut file = create_tmp_file(&tmp_path)?;
        // `mode` 只对"本次新建"生效；崩溃残留的旧 tmp 会被 O_CREAT 复用，
        // 它可能是宽权限，因此创建后再无条件收紧一次。
        tighten_tmp_file(&file)?;
        #[cfg(test)]
        test_hooks::on_tmp_created(&tmp_path);
        file.write_all(bytes)?;
        file.flush()
    })();

    if let Err(error) = written {
        let _ = std::fs::remove_file(&tmp_path);
        // 部署可能让「目录不可写、文件本身可写」（systemd 下把凭据文件放在只读
        // 目录/单文件卷里）。`write_atomically` 之前的原地写只要求文件可写，
        // 因此这里必须与 rename 失败同构地退回原地写，否则比改动前更差（F4）。
        //
        // 只对**权限类**错误回退。tmp 路径的其它失败（ENOSPC / EIO / EDQUOT …）
        // 不能回退：原地写会先截断目标再写，磁盘满时留下半截凭据文件——那正是
        // 原子写要消灭的形态。权限类错误的原地写要么整体成功，要么在 open 阶段
        // 就失败，不会产生半截内容。
        if is_permission_failure(error.kind()) {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "原子写的临时文件无法创建/写入（目录不可写），退回原地写入"
            );
            #[cfg(test)]
            test_faults::record_tmp_fallback();
            std::fs::write(path, bytes)?;
            return Ok(());
        }
        return Err(error.into());
    }

    match rename_tmp(&tmp_path, path) {
        Ok(()) => {
            // 权限在 rename **之后**才放宽回原模式：rename 之前就把含秘密的
            // tmp 设成 0644，等于让窗口期内的内容全局可读（Minor 6）。
            if let Some(permissions) = permissions
                && let Err(error) = std::fs::set_permissions(path, permissions)
            {
                // 内容已经落盘，这里失败只影响权限保真；tmp 仍是 0600，
                // 比"悄悄放宽权限"更接近调用方的期望。
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "写入完成但恢复原文件权限失败，文件保持 0600"
                );
            }
            Ok(())
        }
        Err(rename_error) => {
            tracing::warn!(
                path = %path.display(),
                error = %rename_error,
                "原子 rename 失败（可能是单文件挂载），退回原地写入"
            );
            #[cfg(test)]
            test_faults::record_rename_fallback();
            let _ = std::fs::remove_file(&tmp_path);
            std::fs::write(path, bytes)?;
            Ok(())
        }
    }
}

/// 「这个目录对我不可写」类错误：EACCES / EPERM / EROFS 三种形态。
///
/// 这三类失败都发生在 `open` 阶段，目标文件本身仍然可写，所以退回原地写是
/// 安全的；而 ENOSPC / EIO / EDQUOT 等发生在写入过程中，原地写会截断目标
/// 后写不完，必须如实返回错误。
fn is_permission_failure(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
    )
}

/// 跨模块测试注入点：让本线程下一次 `write_atomically` 在动任何文件之前失败。
///
/// 生产构建里不存在（整块 `#[cfg(test)]`）。线程局部，不影响并行跑的其他用例。
#[cfg(test)]
pub fn inject_write_failure_for_test(kind: std::io::ErrorKind) {
    test_faults::inject_write_failure_public(kind);
}

/// 跨模块测试注入点：让本线程下一次 rename 失败（走「退回原地写」分支）。
#[cfg(test)]
pub fn inject_rename_failure_for_test(kind: std::io::ErrorKind) {
    test_faults::inject_rename_failure_public(kind);
}

/// rename tmp → 目标。
///
/// 生产路径就是 `std::fs::rename`；`#[cfg(test)]` 下允许一次性注入失败，
/// 用来验证「rename 失败退回原地写」这条分支真的存在且不劣于原地写。
fn rename_tmp(tmp_path: &Path, path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(error) = test_faults::fail_rename() {
        return Err(error);
    }
    #[cfg(test)]
    test_hooks::on_before_rename(tmp_path);
    std::fs::rename(tmp_path, path)
}

/// 创建 tmp 文件：unix 上创建即 0600，避免秘密在窗口期内以宽权限落盘。
#[cfg(unix)]
fn create_tmp_file(tmp_path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(TMP_FILE_MODE)
        .open(tmp_path)
}

/// 把已有 tmp 文件的权限收紧到 0600（覆盖崩溃残留的宽权限文件）。
#[cfg(unix)]
fn tighten_tmp_file(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(std::fs::Permissions::from_mode(TMP_FILE_MODE))
}

#[cfg(not(unix))]
fn tighten_tmp_file(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn create_tmp_file(tmp_path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::create(tmp_path)
}

/// 测试用故障注入：只在当前线程、只生效一次。
///
/// 线程局部是刻意的：`cargo test` 并行跑多个用例，进程级开关会误伤别人的写入。
/// 每个用例在自己的线程上打开开关、读走观测值，互不可见。
#[cfg(test)]
mod test_faults {
    use std::cell::RefCell;

    #[derive(Default)]
    struct Faults {
        /// 下一次写 tmp 之前的失败注入
        fail_write: Option<std::io::ErrorKind>,
        /// 下一次 rename 的失败注入
        fail_rename: Option<std::io::ErrorKind>,
        /// 已发生的「rename 失败 → 原地写」回退次数
        rename_fallbacks: usize,
        /// 已发生的「tmp 创建/写入失败 → 原地写」回退次数
        tmp_fallbacks: usize,
    }

    thread_local! {
        static FAULTS: RefCell<Faults> = RefCell::new(Faults::default());
    }

    /// 让本线程下一次 `write_atomically` 在动任何文件之前返回 `kind` 错误。
    pub(super) fn inject_write_failure(kind: std::io::ErrorKind) {
        FAULTS.with(|faults| faults.borrow_mut().fail_write = Some(kind));
    }

    /// 让本线程下一次 rename 失败（走「退回原地写」分支）。
    pub(super) fn inject_rename_failure(kind: std::io::ErrorKind) {
        FAULTS.with(|faults| faults.borrow_mut().fail_rename = Some(kind));
    }

    /// 让本线程下一次 `write_atomically` 的 tmp 创建失败。
    pub(super) fn fail_tmp_creation() -> Option<std::io::Error> {
        FAULTS.with(|faults| {
            let mut faults = faults.borrow_mut();
            faults.fail_write.take().map(std::io::Error::from)
        })
    }

    /// 供跨模块 BDD 使用的公开注入点（仍只在 `#[cfg(test)]` 下存在）。
    pub fn inject_write_failure_public(kind: std::io::ErrorKind) {
        inject_write_failure(kind);
    }

    /// 供跨模块 BDD 使用的公开注入点。
    pub fn inject_rename_failure_public(kind: std::io::ErrorKind) {
        inject_rename_failure(kind);
    }

    pub(super) fn fail_rename() -> Option<std::io::Error> {
        FAULTS
            .with(|faults| faults.borrow_mut().fail_rename.take())
            .map(std::io::Error::from)
    }

    pub(super) fn record_rename_fallback() {
        FAULTS.with(|faults| faults.borrow_mut().rename_fallbacks += 1);
    }

    /// 读走并清空回退计数（线程局部，所以不会被其它用例的写入污染）。
    pub(super) fn take_rename_fallbacks() -> usize {
        FAULTS.with(|faults| std::mem::take(&mut faults.borrow_mut().rename_fallbacks))
    }

    pub(super) fn record_tmp_fallback() {
        FAULTS.with(|faults| faults.borrow_mut().tmp_fallbacks += 1);
    }

    /// 读走并清空「tmp 失败 → 原地写」回退计数。
    pub(super) fn take_tmp_fallbacks() -> usize {
        FAULTS.with(|faults| std::mem::take(&mut faults.borrow_mut().tmp_fallbacks))
    }
}

/// 测试钩子：在 tmp 文件刚创建、内容尚未写入时观测它的权限。
///
/// 生产构建里整段不存在。用 `#[cfg(test)]` 静态槽而不是 sleep，保证断言点
/// 精确落在"创建后、写入前"这个窗口期。
#[cfg(test)]
mod test_hooks {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// 按 tmp 路径记录创建瞬间的权限位。
    ///
    /// 用 path → mode 的映射而不是单槽：`cargo test` 并行跑多个调用方，
    /// 每个用例的 tmp 路径都不同，因此互不覆盖。
    static OBSERVED: Mutex<Option<HashMap<PathBuf, u32>>> = Mutex::new(None);

    fn with_observed<R>(f: impl FnOnce(&mut HashMap<PathBuf, u32>) -> R) -> R {
        // 用例失败会毒化锁；这里恢复内部值，避免后续用例连带 panic。
        let mut guard = OBSERVED.lock().unwrap_or_else(|error| error.into_inner());
        let map = guard.get_or_insert_with(HashMap::new);
        f(map)
    }

    pub(super) fn on_before_rename(tmp_path: &Path) {
        #[cfg(unix)]
        if let Ok(meta) = std::fs::metadata(tmp_path) {
            use std::os::unix::fs::PermissionsExt;
            with_observed(|map| {
                map.insert(rename_key(tmp_path), meta.permissions().mode() & 0o777);
            });
        }
        #[cfg(not(unix))]
        with_observed(|map| {
            map.insert(rename_key(tmp_path), 0);
        });
    }

    /// rename 时刻观测值与创建时刻观测值分开存：同一 tmp 路径要能同时被
    /// 两条断言读到（Minor 6 要证明"创建即 0600 且到 rename 时仍是 0600"）。
    fn rename_key(tmp_path: &Path) -> PathBuf {
        let mut key = tmp_path.to_path_buf();
        key.as_mut_os_string().push("::pre-rename");
        key
    }

    /// 取出并清空某条 tmp 路径在 rename 时刻的权限（Minor 6 观测点）。
    pub(super) fn take_pre_rename(tmp_path: &Path) -> Option<u32> {
        with_observed(|map| map.remove(&rename_key(tmp_path)))
    }

    pub(super) fn on_tmp_created(tmp_path: &Path) {
        #[cfg(unix)]
        if let Ok(meta) = std::fs::metadata(tmp_path) {
            use std::os::unix::fs::PermissionsExt;
            with_observed(|map| {
                map.insert(tmp_path.to_path_buf(), meta.permissions().mode() & 0o777);
            });
        }
        #[cfg(not(unix))]
        with_observed(|map| {
            map.insert(tmp_path.to_path_buf(), 0);
        });
    }

    /// 取出并清空某条 tmp 路径的创建时刻权限。
    pub(super) fn take_observed(tmp_path: &Path) -> Option<u32> {
        with_observed(|map| map.remove(tmp_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 生产路径的 `PermissionsExt` 已经是 `#[cfg(unix)]`；测试侧必须同口径，
    // 否则非 unix 目标上整个测试模块都编译不过。
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("kiro-rs-atomic-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writes_content_and_replaces_existing_file() {
        let dir = temp_dir();
        let path = dir.join("credentials.json");
        std::fs::write(&path, b"old").unwrap();
        write_atomically(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert!(!dir.join("credentials.json.tmp").exists(), "tmp 不应残留");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn preserves_existing_permissions() {
        let dir = temp_dir();
        let path = dir.join("credentials.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_atomically(&path, b"new").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "写回必须保留原文件权限");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn creates_missing_file() {
        let dir = temp_dir();
        let path = dir.join("fresh.json");
        write_atomically(&path, b"{}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 新建文件的最终权限必须是 0600：凭据里有 refreshToken / clientSecret /
    /// 代理密码，不能因为 umask 宽松就落成 0644。
    ///
    /// 反事实：把 `create_tmp_file` 改回 `File::create` 且保留旧的
    /// "目标不存在就不设权限"逻辑，本用例红（实际 0644，取决于 umask）。
    #[cfg(unix)]
    #[test]
    fn new_file_is_owner_only() {
        let dir = temp_dir();
        let path = dir.join("fresh.json");
        write_atomically(&path, b"{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "新建秘密文件必须是属主可读写");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 目标已是 0640 时保留该权限（不把放宽后的既有权限悄悄收紧或放宽）。
    #[cfg(unix)]
    #[test]
    fn preserves_non_default_existing_permissions() {
        let dir = temp_dir();
        let path = dir.join("credentials.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        write_atomically(&path, b"new").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "写回必须保留原文件权限");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// tmp 文件在**创建后、写入前**就是 0600——不是写完才 `set_permissions`。
    ///
    /// 观测点由 `test_hooks::on_tmp_created` 在创建瞬间抓取，不靠 sleep。
    /// 反事实：改回 `File::create` + 末尾 `set_permissions`，本条红
    /// （窗口期内是 0644 或 umask 结果）。
    #[cfg(unix)]
    #[test]
    fn tmp_file_is_owner_only_at_creation() {
        let dir = temp_dir();
        let path = dir.join("fresh.json");
        let tmp_path = path.with_extension("json.tmp");
        let _ = test_hooks::take_observed(&tmp_path);
        write_atomically(&path, b"{}").unwrap();
        let mode = test_hooks::take_observed(&tmp_path).expect("必须观测到 tmp 创建时刻");
        assert_eq!(
            mode, 0o600,
            "凭据/统计的秘密在 tmp 窗口期内不得以宽权限存在"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 崩溃残留的旧 tmp 可能是宽权限：复用它之前必须收紧。
    ///
    /// `O_CREAT` 不会重置既有文件的权限，只设 `mode` 治不了这条路径。
    ///
    /// 反事实：去掉 `tighten_tmp_file` 调用，窗口期观测到 0644，本条红。
    #[cfg(unix)]
    #[test]
    fn stale_tmp_file_is_tightened_before_write() {
        let dir = temp_dir();
        let path = dir.join("credentials.json");
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, b"stale").unwrap();
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = test_hooks::take_observed(&tmp_path);

        write_atomically(&path, b"new").unwrap();
        let mode = test_hooks::take_observed(&tmp_path).expect("必须观测到 tmp 创建时刻");
        assert_eq!(mode, 0o600, "残留 tmp 在写入秘密之前必须被收紧");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 目标是符号链接：写入必须落在**真实目标**上，链接本身保留。
    ///
    /// 缺陷形态：`fs::metadata` 跟随链接拿到"原权限"，随后 rename 替换的是
    /// 目录项里的链接本身——真目标永远拿不到新内容，而失败回退路径的
    /// `fs::write` 却跟随链接写。两条路径语义相反。
    ///
    /// 前置条件断言：`symlink_metadata` 确认目标确实还是符号链接（而不是
    /// 用例建错了），且中间文件确实是普通文件（否则"没被替换"是废话）。
    ///
    /// 反事实（已现场验证）：把 `write_atomically` 的目标改回未解析的 `path`
    /// （即还原 rename 覆盖链接），本条在"目标内容必须更新"处红
    /// （实际 `old`），且 `symlink_metadata` 变成普通文件。
    #[cfg(unix)]
    #[test]
    fn symlink_target_is_written_through_not_replaced() {
        let dir = temp_dir();
        let real = dir.join("real-credentials.json");
        std::fs::write(&real, b"old").unwrap();
        let link = dir.join("credentials.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // 前置条件：链接确实是链接，真目标确实是普通文件。
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "前置条件：credentials.json 必须真的是符号链接"
        );
        assert!(std::fs::symlink_metadata(&real).unwrap().is_file());

        write_atomically(&link, b"new").unwrap();

        assert_eq!(
            std::fs::read(&real).unwrap(),
            b"new",
            "写入必须落在符号链接指向的真实目标上"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "链接必须仍是链接，不能被 rename 换成普通文件"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 目标是符号链接时，真实目标不是 0o600 也不能被悄悄放宽/收紧。
    #[cfg(unix)]
    #[test]
    fn symlink_target_keeps_real_target_permissions() {
        let dir = temp_dir();
        let real = dir.join("real-credentials.json");
        std::fs::write(&real, b"old").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o640)).unwrap();
        let link = dir.join("credentials.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_atomically(&link, b"new").unwrap();

        let mode = std::fs::metadata(&real).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "必须沿用真实目标的原权限");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 原文件 0644 时，tmp 在整个窗口期（含 rename 前一刻）必须是 0600，
    /// 权限只在 rename 之后才落到最终路径。
    ///
    /// 缺陷形态：写完就 `set_permissions(tmp, 原权限)`，再 rename——含秘密的
    /// tmp 在替换前有一段全局可读的窗口。
    ///
    /// 观测点由 `test_hooks::on_before_rename` 在 rename 调用前抓取，不靠 sleep。
    ///
    /// 反事实（已现场验证）：把 `set_permissions(tmp_path, ..)` 挪回 rename
    /// 之前，本条在"rename 前 tmp 必须仍是 0600"处红（实际 0644）。
    #[cfg(unix)]
    #[test]
    fn tmp_stays_owner_only_until_rename() {
        let dir = temp_dir();
        let path = dir.join("credentials.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let tmp_path = path.with_extension("json.tmp");
        let _ = test_hooks::take_pre_rename(&tmp_path);

        write_atomically(&path, b"new").unwrap();

        assert_eq!(
            test_hooks::take_pre_rename(&tmp_path),
            Some(0o600),
            "rename 之前含秘密的 tmp 必须仍是 0600"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "rename 之后最终路径才恢复原权限");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// rename 失败（单文件 bind mount 的真实形态）必须退回原地写：
    /// 内容正确、原文件权限保留、不残留 tmp、且**确实走了回退分支**。
    ///
    /// 前置条件断言：失败是在 rename 这一步注入的（写入与 tmp 均已成功），
    /// 因此"文件里有新内容"只能由回退分支产生。
    ///
    /// 反事实：删掉 `Err(rename_error)` 分支里的 `std::fs::write(path, bytes)`，
    /// 本条红（返回 Err / 内容仍是旧值）。
    #[cfg(unix)]
    #[test]
    fn rename_failure_falls_back_to_in_place_write() {
        let dir = temp_dir();
        let path = dir.join("credentials.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let _ = test_faults::take_rename_fallbacks();

        test_faults::inject_rename_failure(std::io::ErrorKind::PermissionDenied);
        write_atomically(&path, b"new").expect("rename 失败必须退回原地写而不是整体失败");

        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"new",
            "回退写必须落地新内容"
        );
        assert_eq!(
            test_faults::take_rename_fallbacks(),
            1,
            "必须真的走了 rename 失败回退分支（而不是 rename 根本没失败）"
        );
        assert!(
            !dir.join("credentials.json.tmp").exists(),
            "回退路径也必须清掉 tmp"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "原地写沿用文件既有权限，不得被放宽");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 权限类 tmp 失败（目录不可写、文件本身可写）必须退回原地写：
    /// 内容更新、回退分支确实被执行、tmp 不残留。
    ///
    /// # 为什么这条用例的期望从「Err」改成「Ok + 新内容」（F4）
    ///
    /// 旧用例 `write_failure_keeps_original_content_and_returns_error` 用的是
    /// `PermissionDenied`，并断言"写失败必须上抛"。那正是缺陷本身：生产是
    /// systemd 部署，凭据文件可能放在目录不可写的挂载上，此时 tmp 建不出来，
    /// 但目标文件可写——master 的 `fs::write` 在这种部署上能成功，本分支的
    /// 原子写却整体失败，属对 master 的行为回归。因此旧断言与新语义冲突，
    /// 按新语义收窄成"权限类回退 + 非权限类仍上抛"两条（见下一条用例）。
    ///
    /// 前置条件断言：目标文件已存在且内容为 `old`，注入点在 tmp 创建之前，
    /// 所以"最终内容为 new"只能由回退分支产生。
    ///
    /// 反事实：把 tmp 失败分支改回 `return Err(error.into())`（即 F4 的缺陷
    /// 形态），本用例在 `expect` 处红：`tmp 创建失败必须退回原地写而不是整体失败: os error 13`。
    #[cfg(unix)]
    #[test]
    fn tmp_permission_failure_falls_back_to_in_place_write() {
        let dir = temp_dir();
        let path = dir.join("credentials.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let _ = test_faults::take_tmp_fallbacks();

        test_faults::inject_write_failure(std::io::ErrorKind::PermissionDenied);
        write_atomically(&path, b"new")
            .expect("tmp 创建失败（目录不可写）必须退回原地写而不是整体失败");

        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"new",
            "回退写必须落地新内容"
        );
        assert_eq!(
            test_faults::take_tmp_fallbacks(),
            1,
            "必须真的走了 tmp 失败回退分支（而不是 tmp 其实建成功了）"
        );
        assert!(
            !dir.join("credentials.json.tmp").exists(),
            "回退路径也不得留下 tmp"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "原地写沿用文件既有权限，不得被放宽");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 非权限类的 tmp 写入失败（写满 / I/O 错误）仍必须上抛、且目标文件原内容不变。
    ///
    /// 这类失败发生在写入过程中而非 open 阶段：原地写会先截断目标再写不完，
    /// 留下半截凭据文件——那正是原子写要消灭的形态，所以**不许**回退。
    ///
    /// 前置条件断言：失败注入点在任何文件系统操作之前，因此"目标仍是 old"
    /// 证明的是"没有半截内容被发布"，而不是"恰好还没写"。
    ///
    /// 反事实：把 `is_permission_failure` 改成恒 `true`，本条在 `expect_err` 处红
    /// （返回 Ok，且目标是 new）。
    #[test]
    fn non_permission_write_failure_still_returns_error() {
        let dir = temp_dir();
        let path = dir.join("credentials.json");
        std::fs::write(&path, b"old").unwrap();
        let _ = test_faults::take_tmp_fallbacks();

        test_faults::inject_write_failure(std::io::ErrorKind::StorageFull);
        let error = write_atomically(&path, b"new").expect_err("磁盘写满必须上抛");
        assert!(
            error.downcast_ref::<std::io::Error>().is_some(),
            "必须是底层的 io 错误: {error}"
        );
        assert_eq!(
            test_faults::take_tmp_fallbacks(),
            0,
            "非权限类失败不得回退原地写（会留下半截文件）"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"old",
            "失败不得改动目标文件"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
