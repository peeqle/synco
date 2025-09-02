use crate::consts::CommonThreadError;
use crate::diff::files::{attach, get_file, remove, request_file};
use crate::diff::Files;
use crate::get_handle;
use crate::menu::{read_user_input, Action, Step};
use lazy_static::lazy_static;
use log::error;
use std::collections::LinkedList;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use tokio::task::spawn_blocking;
use uuid::Uuid;

type DStep = Box<dyn Step + Send + Sync>;
pub struct FileAction {
    current_step: Option<DStep>,
    steps: Arc<LinkedList<DStep>>,
}

lazy_static! {
    static ref ActionSteps: Arc<LinkedList<DStep>> = Arc::new(LinkedList::from([
        Box::new(SelectFileStep {}) as DStep,
        Box::new(RemoveFileStep {}) as DStep,
        Box::new(DisplayFilesStep {}) as DStep,
        Box::new(RequestFileStep {}) as DStep,
    ]));
}

impl Default for FileAction {
    fn default() -> Self {
        FileAction {
            current_step: None,
            steps: ActionSteps.clone(),
        }
    }
}

impl Action for FileAction {
    fn id(&self) -> String {
        "file_action".to_string()
    }

    fn render(&self) {
        println!("File management");
    }

    fn act(&self) -> Box<dyn Fn() -> Result<bool, CommonThreadError> + Send + Sync> {
        let steps = ActionSteps.clone();
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

struct SelectFileStep {}
impl Step for SelectFileStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let mut valid_file = false;

        while !valid_file {
            println!("Enter file path: ");
            let path_input = read_user_input()?;
            let path = PathBuf::from(path_input);

            let future = spawn_blocking(|| get_handle().block_on(attach(path)));

            let res = futures::executor::block_on(future).expect("Cannot block future");

            match res {
                Ok(_) => {
                    valid_file = true;
                }
                Err(e) => {
                    error!("Cannot perform file attachment! \n {}", e);
                }
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
        "Select files to attach"
    }
}

struct DisplayFilesStep {}
impl Step for DisplayFilesStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let future = spawn_blocking(|| {
            get_handle().block_on(async {
                let cp = Files.clone();
                let mtx = cp.lock().await;

                if mtx.is_empty() {
                    return Err(Box::new(Error::new(ErrorKind::NotFound, "No files")));
                }

                Ok(mtx
                    .iter()
                    .map(|file| format!("{}\t{:?}\t{}", file.id, file.path, file.current_hash))
                    .collect::<Vec<String>>())
            })
        });

        let res = futures::executor::block_on(future).expect("Cannot block future")?;

        if !res.is_empty() {
            println!("Attached files:");
            for i in res {
                println!("{}", i);
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
        "Display attached files"
    }
}

struct RequestFileStep {}
impl Step for RequestFileStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        DisplayFilesStep {}.action()?;

        println!("Select file(ID): ");
        if let Ok(input) = read_user_input() {
            let hypothetical_file_id = Uuid::parse_str(&input)?.to_string();
            let future = spawn_blocking(move || {
                get_handle().block_on(async {
                    let files = {
                        let files = Files.clone();
                        files.lock().await.clone()
                    };

                    if let Some(ent) = get_file(&hypothetical_file_id).await {
                        if ent.is_in_sync {
                            println!("File is already in sync");
                        } else {
                            match request_file(&hypothetical_file_id).await {
                                Ok(_) => {
                                    println!(
                                        "{}",
                                        &format!("Scheduled for synchronization: {}", &hypothetical_file_id)
                                    );
                                }
                                Err(_) => {
                                    println!("{}", &format!("Cannot synchronize: {}", &hypothetical_file_id));
                                }
                            }
                        }
                    }
                })
            });

            futures::executor::block_on(future).expect("Cannot block future");
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
        "Request file"
    }
}

struct RemoveFileStep {}
impl Step for RemoveFileStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        print!("Select file to remove: ");
        let file_id = read_user_input()?;

        let future =
            spawn_blocking(move || get_handle().block_on(async { remove(&file_id).await }));

        let res = futures::executor::block_on(future).expect("Cannot block future");

        match res {
            Ok(_) => {}
            Err(e) => {
                return Err(Box::new(Error::new(
                    ErrorKind::Other,
                    format!("Cannot perform file attachment! \n {}", e),
                )));
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
        "Select files to remove"
    }
}
