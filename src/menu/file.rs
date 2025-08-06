use crate::consts::CommonThreadError;
use crate::diff::{attach, Files};
use crate::menu::{Action, Step};
use log::error;
use std::collections::LinkedList;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::runtime::Runtime;

type DStep = Box<dyn Step>;
pub struct FileAction {
    current_step: Option<DStep>,
    steps: LinkedList<DStep>,
}

impl Default for FileAction {
    fn default() -> Self {
        let select_file_step_instance = Box::new(SelectFileStep {}) as DStep;
        let steps: LinkedList<DStep> = LinkedList::from([select_file_step_instance]);

        FileAction {
            current_step: None,
            steps,
        }
    }
}

impl Action for FileAction {
    fn step(&self) -> u8 {
        todo!()
    }

    fn render(&self) {
        for step in &self.steps {
            step.render();
        }
    }

    fn act(&self) -> Box<dyn Fn() -> Result<(), CommonThreadError>> {
        todo!()
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

    fn next_step(&self) -> Option<Box<dyn Step>> {
        None
    }

    fn render(&self) {
        println!("Select files to attach");
    }
}