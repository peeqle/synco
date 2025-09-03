use crate::consts::CommonThreadError;
use crate::diff::model::SynchroPoint;
use crate::diff::point::SupportedExt::{All, Specified};
use crate::diff::point::{create_point, remove_point, update_point, SupportedExt};
use crate::diff::Points;
use crate::get_handle;
use crate::menu::{read_user_input, Action, Step};
use lazy_static::lazy_static;
use std::ascii::AsciiExt;
use std::collections::LinkedList;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs, io};
use tokio::runtime::Handle;

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
        DisplaySyncPoints {}.action()?;
        println!("Select sync point: ");
        if let Ok(pos) = read_user_input()?.parse::<usize>() {
            let future = get_handle().spawn_blocking(move || {
                get_handle().block_on(async {
                    let existing_points = {
                        let points = Points.clone();
                        points.lock().await.clone()
                    };

                    if let Some((id, point)) = existing_points.iter().nth(pos) {
                        println!("ID\tEXT\t\t\t\tTYPE\t\tPATH\t\t\t\t\tENABLED\t");
                        display_sync_point(pos, id, point);

                        println!("LEAVE BLANK TO LEAVE UNTOUCHED\n---------------------------");
                        println!("Enable point[y/n]:");
                        let enabled_input: bool = match read_user_input() {
                            Ok(input) => {
                                if input.is_empty() {
                                    point.enabled
                                } else {
                                    input.eq_ignore_ascii_case("y")
                                }
                            }
                            Err(_) => false,
                        };

                        println!("Extensions to sync here(blank for skip, Ex.: txt,jpg,pdf):");
                        let extensions_input = read_user_input().expect("Cannot read user input");

                        let mut cooked_extensions = point.ext.clone();
                        if !extensions_input.is_empty() {
                            cooked_extensions = Specified(
                                extensions_input
                                    .split(',')
                                    .map(|x| x.trim().to_string())
                                    .collect(),
                            );
                        }

                        println!("Enter synchronization dir ABSOLUTE path: ");
                        let path_input = read_user_input().expect("Cannot read user input");
                        let mut path = point.path.clone();
                        if !path_input.is_empty() {
                            path = PathBuf::from(path_input);
                            verify_path(&path);
                        }

                        if update_point(
                            id.clone(),
                            cooked_extensions,
                            Some(path),
                            Some(enabled_input),
                        )
                        .await
                        .is_err()
                        {
                            println!("Cannot update selected point");
                        }
                    }
                });
            });
            futures::executor::block_on(future).expect("Cannot block");
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

struct CreateSyncPoint {}
impl Step for CreateSyncPoint {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let future = get_handle().spawn_blocking(move || {
            get_handle().block_on(async {
                let path = get_path()
                    .expect("Cannot read provided path");

                println!("Enable point[y/n]:");
                let enabled_input: bool = read_user_input()
                    .unwrap_or("n".to_owned())
                    .eq_ignore_ascii_case("y");

                let cooked_extensions = get_extensions(None);

                create_point(SynchroPoint {
                    ext: cooked_extensions,
                    path,
                    enabled: enabled_input,
                })
                .await
            })
        });

        if let Err(_) = futures::executor::block_on(future) {
            print!("Error while creating new point...");
        }
        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        todo!()
    }

    fn invoked(&self) -> bool {
        todo!()
    }

    fn render(&self) {
        todo!()
    }

    fn display(&self) -> &str {
        todo!()
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
                println!("N\tID\t\t\t\t\tTYPE\tPATH\t\t\t\t\tENABLED\t");
                for (idx, (ext, point)) in mtx.iter().enumerate() {
                    display_sync_point(idx, ext, point);
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

fn display_sync_point(pos: usize, id: &String, point: &SynchroPoint) {
    let mut extensions_unwrapped = String::new();
    match &point.ext {
        SupportedExt::Specified(vec) => {
            vec.iter().for_each(|x| {
                extensions_unwrapped.push_str(x);
                extensions_unwrapped.push_str(" ");
            });
        }
        SupportedExt::All => {
            extensions_unwrapped.push_str("ALL");
        }
    }
    println!(
        "{}\t{}\t{}\t{:?}\t{}",
        pos, id, extensions_unwrapped, point.path, point.enabled
    );
}

fn get_path() -> Result<PathBuf, CommonThreadError> {
    println!("Enter synchronization dir ABSOLUTE path: ");
    let path_input = read_user_input().expect("Cannot read user input");

    if path_input.is_empty() {
        return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Path cannot be empty")));
    }
    let path = PathBuf::from(path_input);
    verify_path(&path);

    Ok(path)
}

fn verify_path(path: &PathBuf) {
    if !&path.exists() || !&path.is_absolute() {
        println!("Cannot resolve provided path: {:?}", path);
        println!("Create dirs at {:?} ?[y/n]", path);
        if read_user_input()
            .expect("Cannot read input")
            .eq_ignore_ascii_case("y")
        {
            fs::create_dir_all(path).expect("Cannot create dirs");
        }
    }
}

fn get_extensions(initial: Option<SupportedExt>) -> SupportedExt {
    println!("Extensions to sync here(blank for skip, Ex.: txt,jpg,pdf):");
    let extensions_input = read_user_input().expect("Cannot read user input");
    let mut cooked_extensions = initial.unwrap_or(All);
    if !extensions_input.is_empty() {
        cooked_extensions = Specified(
            extensions_input
                .split(',')
                .map(|x| x.trim().to_string())
                .collect(),
        );
    }
    cooked_extensions
}
