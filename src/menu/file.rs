use crate::consts::CommonThreadError;
use crate::diff::files::{attach, remove};
use crate::diff::Files;
use crate::menu::{read_user_input, Action, Step};
use crate::menu_step;
use lazy_static::lazy_static;
use log::error;
use std::collections::LinkedList;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use tokio::runtime::Runtime;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;

type DStep = Box<dyn Step + Send + Sync>;
pub struct FileAction {
    current_step: Option<DStep>,
    steps: Arc<LinkedList<DStep>>,
}

lazy_static! {
    static ref ActionSteps: Arc<LinkedList<DStep>> = Arc::new(LinkedList::from([
        Box::new(SelectFileStep::default()) as DStep,
        Box::new(RemoveFileStep::default()) as DStep,
        Box::new(DisplayFilesStep::default()) as DStep,
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

menu_step!(SelectFileStep);
impl Step for SelectFileStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let mut valid_file = false;

        while !valid_file {
            println!("Enter file path: ");
            let path_input = read_user_input()?;
            let path = PathBuf::from(path_input);

            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let rt = Runtime::new().expect("Failed to create Tokio runtime");
                let res = rt.block_on(attach(path));
                let _ = tx.send(res);
            });

            match rx.recv() {
                Ok(Ok(())) => {
                    valid_file = true;
                }
                Ok(Err(e)) => {
                    error!("Cannot perform file attachment! \n {}", e);
                }
                Err(_) => {}
            }
        }
        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        self.invoked.load(SeqCst)
    }

    fn render(&self) {
        print!("Select files to attach");
    }

    fn display(&self) -> &str {
        "Select files to attach"
    }
}

menu_step!(DisplayFilesStep);
impl Step for DisplayFilesStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = Runtime::new().expect("Failed to create Tokio runtime");
            let result = rt.block_on(async {
                let files = Files.clone();
                let mtx_guard = files.lock().await;

                let formatted_strings: Vec<String> = mtx_guard
                    .iter()
                    .map(|(_, file)| format!("{}\t{:?}\t{}", file.id, file.path, file.current_hash))
                    .collect();

                formatted_strings
            });
            let _ = tx.send(result);
        });

        if let Ok(result) = rx.recv() {
            println!("Attached files:");
            for i in result {
                println!("{}", i);
            }
        }

        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        self.invoked.load(SeqCst)
    }

    fn render(&self) {
        print!("Display attached files");
    }

    fn display(&self) -> &str {
        "Display attached files"
    }
}

menu_step!(RemoveFileStep);
impl Step for RemoveFileStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        print!("Select file to remove: ");
        let file_id = read_user_input()?;

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = Runtime::new().expect("Failed to create Tokio runtime");
            let res = rt.block_on(remove(&file_id));
            let _ = tx.send(res);
        });

        match rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(Box::new(Error::new(
                    ErrorKind::Other,
                    format!("Cannot perform file attachment! \n {}", e),
                )));
            }
            Err(_) => {}
        }
        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        self.invoked.load(SeqCst)
    }

    fn render(&self) {
        print!("Select files to remove")
    }

    fn display(&self) -> &str {
        "Select files to remove"
    }
}
