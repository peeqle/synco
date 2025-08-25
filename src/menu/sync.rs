use crate::consts::CommonThreadError;
use crate::diff::point::{remove_point, update_point};
use crate::diff::{Files, Points};
use crate::menu::{read_user_input, Action, Step};
use crate::menu_step;
use lazy_static::lazy_static;
use log::error;
use std::collections::LinkedList;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{mpsc, Arc};
use std::{fs, io};
use tokio::runtime::{Handle, Runtime};

type DStep = Box<dyn Step + Send + Sync>;
pub struct SyncAction {
    current_step: Option<DStep>,
    steps: Arc<LinkedList<DStep>>,
}

lazy_static! {
    static ref ActionSteps: Arc<LinkedList<DStep>> = Arc::new(LinkedList::from([
        Box::new(UpdateSyncPoint {}) as DStep,
        Box::new(RemoveSyncPoint {}) as DStep,
        Box::new(DisplaySyncPoints {}) as DStep,
    ]));
}

impl Default for SyncAction {
    fn default() -> Self {
        SyncAction {
            current_step: None,
            steps: ActionSteps.clone(),
        }
    }
}

impl Action for SyncAction {
    fn id(&self) -> String {
        "sync_action".to_string()
    }

    fn render(&self) {
        println!("Synchronization management");
    }

    fn act(&self) -> Box<dyn Fn() -> Result<bool, CommonThreadError> + Send + Sync> {
        let steps = self.steps.clone();
        Box::new(move || {
            println!("Select option:");
            for (id, x) in steps.iter().enumerate() {
                println!("\t{} {}", id, x.display());
            }

            match read_user_input() {
                Ok(val) => match val.parse::<usize>() {
                    Ok(n) if n < steps.len() => steps.iter().nth(n).unwrap().action(),
                    _ => {
                        println!("Unknown option");
                        Ok(false)
                    }
                },
                Err(_) => {
                    println!("Cannot read user input");
                    Ok(false)
                }
            }
        })
    }
}

struct UpdateSyncPoint {}
impl Step for UpdateSyncPoint {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let handle = Handle::current();
        let mut valid_input = false;

        while !valid_input {
            println!("Enter synchronization dir ABSOLUTE path: ");
            let path_input = read_user_input()?;
            let path = PathBuf::from(path_input);

            let mut point_creation = |path: PathBuf| -> Result<(), CommonThreadError> {
                println!("Enable point[y/n]:");
                let enabled_input = read_user_input()?;

                println!("Extensions to sync here(blank for all, Ex.: txt,jpg,pdf):");
                let extensions_input = read_user_input()?;

                let mut cooked_extensions = Vec::new();
                if !extensions_input.is_empty() {
                    cooked_extensions = extensions_input
                        .split(',')
                        .map(|x| x.trim().to_string())
                        .collect();
                }

                let (tx, rx) = mpsc::channel::<Result<(), CommonThreadError>>();

                let handle_clone = handle.clone();
                handle.spawn_blocking(move || {
                    let result = handle_clone.block_on(async {
                        let runtime_handle_update = |ext, path, enabled_input: String| {
                            update_point(
                                ext,
                                Some(path),
                                match enabled_input.is_empty() {
                                    true => Some(true),
                                    false => Some(enabled_input.to_ascii_lowercase() == "y"),
                                },
                            )
                        };

                        if cooked_extensions.is_empty() {
                            runtime_handle_update(
                                "ALL".to_string(),
                                path.clone(),
                                enabled_input.clone(),
                            )
                            .await
                            .expect("Cannot send update for Point");
                            let _ = tx.send(Ok(()));
                        } else {
                            for ext in cooked_extensions {
                                runtime_handle_update(ext, path.clone(), enabled_input.clone())
                                    .await
                                    .expect("Cannot send update for Point");
                            }
                            let _ = tx.send(Ok(()));
                        }
                        Ok(())
                    });
                    let _ = tx.send(result);
                });

                match rx.recv() {
                    Ok(Ok(())) => {
                        valid_input = true;
                    }
                    Ok(Err(e)) => {
                        error!("Cannot perform point update! \n {}", e);
                    }
                    Err(_) => {}
                }
                Ok(())
            };

            if !&path.exists() || !&path.is_absolute() {
                println!("Cannot resolve provided path: {:?}", path);
                println!("Create dirs at {:?} ?[y/n]", path);
                if read_user_input()?.to_ascii_lowercase() == "y" {
                    fs::create_dir_all(&path)?;
                    point_creation(path.clone())?;
                }
            } else {
                point_creation(path.clone())?;
            }
        }
        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        false
    }

    fn render(&self) {
        print!("{}", self.display());
    }

    fn display(&self) -> &str {
        "Update files mount point"
    }
}

struct DisplaySyncPoints {}
impl Step for DisplaySyncPoints {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let handle = Handle::current();

        tokio::task::block_in_place(|| {
            let points = Points.clone();
            handle.block_on(async {
                let mtx = points.lock().await;
                println!("idx\tTYPE\tPATH\t\t\t\t\tENABLED\t");
                for (idx, (ext, point)) in mtx.iter().enumerate() {
                    println!("{}\t{}\t{:?}\t{}", idx, ext, point.path, point.enabled);
                }
            });
        });
        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        false
    }

    fn render(&self) {
        print!("{}", self.display());
    }

    fn display(&self) -> &str {
        "Display existing points"
    }
}

struct RemoveSyncPoint {}
impl Step for RemoveSyncPoint {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let handle = Handle::current();

        let file_extension_to_remove = read_user_input()?;
        if file_extension_to_remove.is_empty() {
            println!("Missclick bud...");
        } else {
            tokio::task::block_in_place(|| {
                handle.block_on(remove_point(file_extension_to_remove))
            })?;
        }

        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        false
    }

    fn render(&self) {
        print!("Select files to remove")
    }

    fn display(&self) -> &str {
        "Select files to remove"
    }
}
