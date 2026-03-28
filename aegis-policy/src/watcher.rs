//! Hot-reload policy watcher using the `notify` crate.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use aegis_core::TokenRequest;

use crate::compiler::PolicyCompiler;
use crate::error::PolicyError;

/// Callback type invoked when policies are reloaded.
pub type ReloadCallback = Box<dyn Fn(&[TokenRequest]) + Send + Sync>;

/// Watches a policy file or directory for changes and recompiles on modification.
pub struct PolicyWatcher {
    /// The compiled policies (latest successful load).
    policies: Arc<Mutex<Vec<TokenRequest>>>,
    /// The underlying filesystem watcher (kept alive to maintain subscription).
    _watcher: RecommendedWatcher,
    /// Path being watched.
    path: PathBuf,
}

impl PolicyWatcher {
    /// Creates a new watcher that monitors `path` for changes.
    ///
    /// Performs an initial compile, then watches for filesystem changes.
    /// When a change is detected, recompiles and updates the stored policies.
    /// If recompilation fails, the previous valid policies are kept.
    ///
    /// The optional `on_reload` callback is invoked after each successful reload.
    pub fn new(
        path: impl AsRef<Path>,
        on_reload: Option<ReloadCallback>,
    ) -> Result<Self, PolicyError> {
        let path = path.as_ref().to_path_buf();
        let compiler = PolicyCompiler::new();

        // Initial compile
        let initial = load_policies(&compiler, &path)?;
        let policies = Arc::new(Mutex::new(initial));

        // Set up watcher
        let policies_clone = Arc::clone(&policies);
        let path_clone = path.clone();
        let on_reload = on_reload.map(Arc::new);

        let mut watcher =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                let event = match res {
                    Ok(e) => e,
                    Err(_) => return,
                };

                // Only react to content changes
                match event.kind {
                    EventKind::Modify(_) | EventKind::Create(_) => {}
                    _ => return,
                }

                let compiler = PolicyCompiler::new();
                match load_policies(&compiler, &path_clone) {
                    Ok(new_policies) => {
                        if let Some(ref cb) = on_reload {
                            cb(&new_policies);
                        }
                        *policies_clone.lock().unwrap() = new_policies;
                    }
                    Err(_) => {
                        // Keep previous valid policies on error
                    }
                }
            })
            .map_err(|e| PolicyError::Watcher(e.to_string()))?;

        // Watch the file or directory
        let watch_path = if path.is_dir() {
            path.clone()
        } else {
            path.parent().unwrap_or(&path).to_path_buf()
        };
        watcher
            .watch(&watch_path, RecursiveMode::NonRecursive)
            .map_err(|e| PolicyError::Watcher(e.to_string()))?;

        Ok(Self {
            policies,
            _watcher: watcher,
            path,
        })
    }

    /// Returns the currently loaded policies.
    pub fn policies(&self) -> Vec<TokenRequest> {
        self.policies.lock().unwrap().clone()
    }

    /// Returns the path being watched.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Forces a manual reload from disk.
    pub fn reload(&self) -> Result<Vec<TokenRequest>, PolicyError> {
        let compiler = PolicyCompiler::new();
        let new_policies = load_policies(&compiler, &self.path)?;
        *self.policies.lock().unwrap() = new_policies.clone();
        Ok(new_policies)
    }
}

/// Loads policies from a path (file or directory of .yaml/.yml files).
fn load_policies(compiler: &PolicyCompiler, path: &Path) -> Result<Vec<TokenRequest>, PolicyError> {
    if path.is_dir() {
        let mut all = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let p = e.path();
                p.extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
            .collect();
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let mut policies = compiler.compile_file(&entry.path())?;
            all.append(&mut policies);
        }
        Ok(all)
    } else {
        compiler.compile_file(path)
    }
}
