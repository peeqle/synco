use crate::consts::CommonThreadError;
use crate::diff::point::{remove_point, update_point};
use crate::diff::{attach, remove, Files, Points};
use crate::menu::{read_user_input, Action, Step};
use log::error;
use std::collections::LinkedList;
use std::io;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::mpsc;
use tokio::runtime::{Handle, Runtime};

type DStep = Box<dyn Step + Send + Sync>;
pub struct SyncAction {
    current_step: Option<DStep>,
    steps: LinkedList<DStep>,
}

impl Default for SyncAction {
    fn default() -> Self {
        let steps: LinkedList<DStep> = LinkedList::from([
            Box::new(UpdateSyncPoint {}) as DStep,
            Box::new(RemoveSyncPoint {}) as DStep,
            Box::new(DisplaySyncPoints {}) as DStep,
        ]);

        SyncAction {
            current_step: None,
            steps,
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
        Box::new(|| {
            let steps: Vec<DStep> = vec![
                Box::new(UpdateSyncPoint {}),
                Box::new(RemoveSyncPoint {}),
                Box::new(DisplaySyncPoints {}),
            ];

            println!("Select option:");
            for (id, x) in steps.iter().enumerate() {
                println!("\t{} {}", id, x.display());
            }

            match read_user_input() {
                Ok(val) => match val.parse::<usize>() {
                    Ok(n) if n < steps.len() => steps[n].action(),
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
        let mut valid_input = false;

        while !valid_input {
            println!("Enter synchronization dir path: ");
            let path_input = read_user_input()?;
            let path = PathBuf::from(path_input);

            if !&path.exists() {
                println!("Cannot resolve provided path: {:?}", path);
            } else {
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
                std::thread::spawn(move || {
                    let handle = Handle::current();

                    let runtime_handle_update = |ext, path, enabled_input: &String| {
                        tokio::task::block_in_place(|| {
                            handle
                                .block_on(update_point(
                                    ext,
                                    Some(path),
                                    match enabled_input.is_empty() {
                                        true => Some(true),
                                        false => Some(enabled_input.to_ascii_lowercase() == "y"),
                                    },
                                ))
                                .expect("TODO: panic message");
                        });
                    };

                    if cooked_extensions.is_empty() {
                        runtime_handle_update("ALL".to_string(), path.clone(), &enabled_input);
                    } else {
                        for ext in cooked_extensions {
                            runtime_handle_update(ext, path.clone(), &enabled_input);
                        }
                    }
                    let _ = tx.send(Ok(()));
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
            }
        }
        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
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
        }else {
            tokio::task::block_in_place(|| handle.block_on(remove_point(file_extension_to_remove)))?;
        }

        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn render(&self) {
        print!("Select files to remove")
    }

    fn display(&self) -> &str {
        "Select files to remove"
    }
}
