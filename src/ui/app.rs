use super::{FilesModule, LogsModule, NetworkModule, PerformanceModule, SettingsModule};
use crate::chain::{ModuleConfig, ModuleEvent, ModuleManager, SystemEvent, UIEvent};
use crate::consts::DeviceId;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend, layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Tabs},
    Frame
    ,
    Terminal,
};
use std::collections::HashMap;
use std::io;
use std::time::Duration;
use tokio::time::sleep;

pub struct SyncoUI {
    pub should_quit: bool,
    pub selected_tab: usize,
    pub module_manager: ModuleManager,
}

impl SyncoUI {
    pub fn new() -> Self {
        // Create module configuration
        let config = ModuleConfig {
            enabled_modules: vec![
                "network".to_string(),
                "files".to_string(),
                "logs".to_string(),
                "performance".to_string(),
                "settings".to_string(),
            ],
            module_settings: HashMap::new(),
        };

        // Create module manager
        let mut module_manager = ModuleManager::new(config);

        // Register UI modules
        module_manager.register_ui_module(Box::new(NetworkModule::new()));
        module_manager.register_ui_module(Box::new(FilesModule::new()));
        module_manager.register_ui_module(Box::new(LogsModule::new()));
        module_manager.register_ui_module(Box::new(PerformanceModule::new()));
        module_manager.register_ui_module(Box::new(SettingsModule::new()));

        Self {
            should_quit: false,
            selected_tab: 0,
            module_manager,
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Initialize all modules first
        self.module_manager.init_all().await.map_err(|e| format!("Failed to initialize modules: {}", e))?;

        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Emit startup events
        self.module_manager.handle_event(ModuleEvent::System(SystemEvent::Startup)).await
            .map_err(|e| format!("Failed to handle startup event: {}", e))?;

        // Main loop
        loop {
            terminal.draw(|f| self.draw(f))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    // Handle global UI events first
                    match key.code {
                        KeyCode::Char('q') => {
                            self.should_quit = true;
                        }
                        KeyCode::Tab => {
                            let ui_modules = self.module_manager.get_ui_modules();
                            self.selected_tab = (self.selected_tab + 1) % ui_modules.len();
                            self.module_manager.handle_event(ModuleEvent::UI(UIEvent::TabChanged(self.selected_tab))).await
                                .map_err(|e| format!("Failed to handle tab change: {}", e))?;
                        }
                        KeyCode::Char('1'..='9') => {
                            if let Some(digit) = key.code.to_string().chars().next() {
                                if let Some(tab_num) = digit.to_digit(10) {
                                    let ui_modules = self.module_manager.get_ui_modules();
                                    let new_tab = (tab_num as usize).saturating_sub(1);
                                    if new_tab < ui_modules.len() {
                                        self.selected_tab = new_tab;
                                        self.module_manager.handle_event(ModuleEvent::UI(UIEvent::TabChanged(self.selected_tab))).await
                                            .map_err(|e| format!("Failed to handle tab change: {}", e))?;
                                    }
                                }
                            }
                        }
                        _ => {
                            // Forward key event to current UI module
                            self.handle_module_ui_event(key).await?;

                            // Also emit general key press event
                            self.module_manager.handle_event(ModuleEvent::UI(UIEvent::KeyPressed(format!("{:?}", key.code)))).await
                                .map_err(|e| format!("Failed to handle key press: {}", e))?;
                        }
                    }
                }
            }

            if self.should_quit {
                break;
            }

            // Emit periodic refresh events
            self.module_manager.handle_event(ModuleEvent::UI(UIEvent::Refresh)).await
                .map_err(|e| format!("Failed to handle refresh: {}", e))?;

            sleep(Duration::from_millis(50)).await;
        }

        // Shutdown modules
        self.module_manager.shutdown().await
            .map_err(|e| format!("Failed to shutdown modules: {}", e))?;

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        Ok(())
    }

    async fn handle_module_ui_event(&mut self, key: KeyEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ui_modules = self.module_manager.get_ui_modules();
        if let Some(module) = ui_modules.get(self.selected_tab) {
            // We can't directly call handle_ui_event on the module through the trait object
            // In a real implementation, you'd need a different approach for mutable access
            // For now, we'll emit events that the modules can respond to
            match key.code {
                KeyCode::Up => {
                    self.module_manager.handle_event(ModuleEvent::Custom {
                        event_type: "ui_navigation".to_string(),
                        data: serde_json::json!({"direction": "up"}),
                    }).await.map_err(|e| format!("Failed to handle navigation: {}", e))?;
                }
                KeyCode::Down => {
                    self.module_manager.handle_event(ModuleEvent::Custom {
                        event_type: "ui_navigation".to_string(),
                        data: serde_json::json!({"direction": "down"}),
                    }).await.map_err(|e| format!("Failed to handle navigation: {}", e))?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Length(3), // Tab bar
                Constraint::Min(0),    // Main content
                Constraint::Length(3), // Footer
            ])
            .split(f.area());

        self.draw_header(f, chunks[0]);
        self.draw_tab_bar(f, chunks[1]);
        self.draw_main_content(f, chunks[2]);
        self.draw_footer(f, chunks[3]);
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let module_count = self.module_manager.get_ui_modules().len();
        let header = Paragraph::new(format!(
            "Synco - P2P File Sync | Device ID: {} | Modules: {}",
            &DeviceId[..8],
            module_count
        ))
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(header, area);
    }

    fn draw_tab_bar(&self, f: &mut Frame, area: Rect) {
        let ui_modules = self.module_manager.get_ui_modules();
        let tab_names: Vec<String> = ui_modules
            .iter()
            .enumerate()
            .map(|(i, module)| format!("[{}] {}", i + 1, module.tab_name()))
            .collect();

        let tabs = Tabs::new(tab_names)
            .block(Block::default().borders(Borders::ALL).title("Modules"))
            .style(Style::default().fg(Color::White))
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .bg(Color::Blue)
                    .fg(Color::Yellow)
            )
            .select(self.selected_tab);

        f.render_widget(tabs, area);
    }

    fn draw_main_content(&self, f: &mut Frame, area: Rect) {
        let ui_modules = self.module_manager.get_ui_modules();

        if let Some(module) = ui_modules.get(self.selected_tab) {
            let context = self.module_manager.get_context();
            module.draw(f, area, context);
        } else {
            // Fallback content if no module is available
            let error_msg = Paragraph::new("No module available")
                .style(Style::default().fg(Color::Red))
                .block(Block::default().borders(Borders::ALL).title("Error"));
            f.render_widget(error_msg, area);
        }
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let ui_modules = self.module_manager.get_ui_modules();
        let current_module_name = ui_modules
            .get(self.selected_tab)
            .map(|m| m.tab_name())
            .unwrap_or("None");

        let footer = Paragraph::new(format!(
            "Press 'q' to quit | Tab/1-{} to switch | Current: {} | Global events system active",
            ui_modules.len(),
            current_module_name
        ))
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, area);
    }
}

pub async fn start_ui() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ui = SyncoUI::new();
    ui.run().await
}
