mod file;
mod server;

use crate::consts::CommonThreadError;
use crate::menu::file::FileAction;
use crate::menu::server::ServerAction;
use lazy_static::lazy_static;
use log::error;
use serde::de::Error;
use std::collections::HashMap;
use std::io;

lazy_static! {
    static ref ActionMap: HashMap<i64, Box<dyn Action + Send + Sync>> = {
        let mut map = HashMap::new();
        map.insert(0, Box::new(FileAction::default()) as Box<dyn Action + Send + Sync>);
        map.insert(1, Box::new(ServerAction::default()) as Box<dyn Action + Send + Sync>);
        
        map
    };
}

pub fn display_menu() {
    loop {
        for (id, entry) in ActionMap.iter() {
            println!("{}. {:?}", id, entry.render());
        }
        println!("Select menu option:");

        if let Err(e) = read_user_input() {
            error!("Cannot read user input!")
        }
        println!();
        #[cfg(unix)]
        {
            std::process::Command::new("clear").status().unwrap();
        }
        #[cfg(windows)]
        {
            std::process::Command::new("cls").status().unwrap();
        }
    }
}

pub fn read_user_input() -> Result<String, CommonThreadError> {
    let stdin = io::read_to_string(io::stdin())?;
    Ok(stdin)
}

pub trait Action: Send + Sync {
    fn id(&self) -> String;
    fn render(&self);
    fn act(&self) -> Box<dyn Fn() -> Result<(), CommonThreadError> + Send + Sync>;
}

trait Step: Send + Sync {
    fn action(&self) -> Result<(), CommonThreadError>;
    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>>;
    fn render(&self);
    fn display(&self) -> &str;
}