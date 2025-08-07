use crate::consts::CommonThreadError;
use crate::diff::{attach, remove, Files};
use crate::menu::{read_user_input, Action, Step};
use log::error;
use std::collections::LinkedList;
use std::fmt::format;
use std::io;
use std::io::{Error, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
                Box::new(DisplayFilesStep {}) as DStep
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
        for (id, x) in self.steps.iter().enumerate() {
            println!("\t{} {:?}", id, x.display());
        }
    }

    fn act(&self) -> Box<dyn Fn() -> Result<(), CommonThreadError> + Send + Sync> {
        Box::new(|| {
            let select_step = SelectFileStep {};
            select_step.action()
        })
    }
}


struct SelectFileStep {}
impl Step for SelectFileStep {
    fn action(&self) -> Result<(), CommonThreadError> {
        let mut valid_file = false;

        while !valid_file {
            let mut path_input = String::new();
            io::stdin()
                .read_line(&mut path_input)
                .expect("Cannot read th input");

            {
                let path = PathBuf::from(path_input);

                let rt = Runtime::new().expect("Failed to create Tokio runtime");
                if let Err(e) = rt.block_on(attach(path)) {
                    error!("Cannot perform file attachment! \n {}", e);
                } else {
                    valid_file = true;
                }
            }
        }
        Ok(())
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
    fn action(&self) -> Result<(), CommonThreadError> {
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

        println!("Attached files:");
        for i in result {
            println!("{}", i);
        }

        Ok(())
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

struct RemoveFileStep {}
impl Step for RemoveFileStep {
    fn action(&self) -> Result<(), CommonThreadError> {
        print!("Select file to remove: ");
        let file_id = read_user_input()?;

        let rt = Runtime::new().expect("Failed to create Tokio runtime");
        if let Err(e) = rt.block_on(remove(&file_id)) {
            return Err(Box::new(Error::new(ErrorKind::Other, format!("Cannot perform file attachment! \n {}", e))));
        }
        Ok(())
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