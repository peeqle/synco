use crate::consts::CommonThreadError;
use crate::diff::{attach, remove, Files};
use crate::menu::{read_user_input, Action, Step};
use log::error;
use std::collections::LinkedList;
use std::io;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::mpsc;
use tokio::runtime::Runtime;

type DStep = Box<dyn Step + Send + Sync>;
pub struct FileAction {
    current_step: Option<DStep>,
    steps: LinkedList<DStep>,
}

impl Default for FileAction {
    fn default() -> Self {
        let steps: LinkedList<DStep> = LinkedList::from(
            [
                Box::new(SelectFileStep {}) as DStep,
                Box::new(RemoveFileStep {}) as DStep,
                Box::new(DisplayFilesStep {}) as DStep,
            ]
        );

        FileAction {
            current_step: None,
            steps,
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
        Box::new(|| {
            let steps: Vec<DStep> = vec![
                Box::new(SelectFileStep {}),
                Box::new(RemoveFileStep {}),
                Box::new(DisplayFilesStep {}),
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


struct SelectFileStep {}
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

    fn render(&self) {
        print!("Select files to attach");
    }

    fn display(&self) -> &str {
        "Select files to attach"
    }
}

struct DisplayFilesStep {}
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
                    .map(|(_, file)| {
                        format!("{}\t{:?}\t{}", file.id, file.path, file.current_hash)
                    })
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

    fn render(&self) {
        print!("Display attached files");
    }

    fn display(&self) -> &str {
        "Display attached files"
    }
}

struct RemoveFileStep {}
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
                return Err(Box::new(Error::new(ErrorKind::Other, format!("Cannot perform file attachment! \n {}", e))))
            }
            Err(_) => {}
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