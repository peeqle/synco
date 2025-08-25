mod file;
mod server;
mod sync;

use crate::consts::CommonThreadError;
use crate::menu::file::FileAction;
use crate::menu::server::ServerAction;
use crate::menu::sync::SyncAction;
use lazy_static::lazy_static;
use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::AtomicBool;

lazy_static! {
    static ref ActionMap: BTreeMap<i64, Box<dyn Action + Send + Sync>> = {
        let mut map = BTreeMap::new();
        map.insert(0, Box::new(FileAction::default()) as Box<dyn Action + Send + Sync>);
        map.insert(1, Box::new(ServerAction::default()) as Box<dyn Action + Send + Sync>);
        map.insert(2, Box::new(SyncAction::default()) as Box<dyn Action + Send + Sync>);

        map
    };
}

pub fn display_menu() {
    loop {
        for (id, entry) in ActionMap.iter() {
            print!("{}.", id);
            entry.render();
        }
        println!("Select menu option:");

        match read_user_input() {
            Ok(val) => {
                match val.parse::<i64>() {
                    Ok(n) => {
                        if let Some(entry) = ActionMap.get(&n) {
                            let action = entry.act();

                            match action() {
                                Ok(shutdown_menu) => {
                                    if shutdown_menu {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    println!("{}", e);
                                }
                            }
                        } else {
                            println!("Unknown menu option");
                        }
                    }
                    Err(_) => {
                        println!("Cannot resolve user input, try again");
                    }
                }
            }
            Err(_) => {
                println!("Cannot read user input!");
            }
        }
    }
}

pub fn read_user_input() -> Result<String, CommonThreadError> {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    buffer = buffer.replace("\n", "");
    Ok(buffer)
}

pub trait Action: Send + Sync {
    fn id(&self) -> String;
    fn render(&self);
    fn act(&self) -> Box<dyn Fn() -> Result<bool, CommonThreadError> + Send + Sync>;
}

pub trait Step: Send + Sync {
    fn action(&self) -> Result<bool, CommonThreadError>;
    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>>;
    fn invoked(&self) -> bool;
    fn render(&self);
    fn display(&self) -> &str;
}

#[macro_export]
macro_rules!  menu_step {

    ($name: ident) => {
        pub struct $name {
            invoked: AtomicBool
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    invoked: AtomicBool::new(false)
                }
            }
        }
    };
}