mod file;
mod server;

use crate::consts::CommonThreadError;
use crate::menu::file::FileAction;

fn get_mods() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(FileAction::default())
    ]
}

trait Action {
    fn step(&self) -> u8;
    fn render(&self);
    fn act(&self) -> Box<dyn Fn() -> Result<(), CommonThreadError>>;
}

trait Step {
    fn action(&self) -> Result<(), CommonThreadError>;
    fn next_step(&self) -> Option<Box<dyn Step>>;
    fn render(&self);
}