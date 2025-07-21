use crate::chain::{UIModule, Module, ModuleContext, ModuleEvent, EventResult, ModuleError, ModuleMetadata, SystemEvent, UIEvent, NetworkEvent, FileSystemEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Modifier},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Gauge, Clear},
};
use async_trait::async_trait;
use crossterm::event::KeyEvent;
use std::collections::VecDeque;

pub struct LogsModule {
    log_entries: VecDeque<LogEntry>,
    max_entries: usize,
    selected_index: usize,
    filter_level: LogLevel,
    auto_scroll: bool,
    show_details: bool,
    statistics: LogStatistics,
}

#[derive(Clone, Debug)]
struct LogEntry {
    timestamp: std::time::SystemTime,
    level: LogLevel,
    source: String,
    message: String,
    details: Option<String>,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Debug, Default)]
struct LogStatistics {
    total_entries: usize,
    debug_count: usize,
    info_count: usize,
    warning_count: usize,
    error_count: usize,
    critical_count: usize,
}

impl LogsModule {
    pub fn new() -> Self {
        Self {
            log_entries: VecDeque::with_capacity(1000),
            max_entries: 1000,
            selected_index: 0,
            filter_level: LogLevel::Debug,
            auto_scroll: true,
            show_details: false,
            statistics: LogStatistics::default(),
        }
    }
    
    fn add_log_entry(&mut self, level: LogLevel, source: String, message: String, details: Option<String>) {
        if self.log_entries.len() >= self.max_entries {
            self.log_entries.pop_front();
        }
        
        let entry = LogEntry {
            timestamp: std::time::SystemTime::now(),
            level: level.clone(),
            source,
            message,
            details,
        };
        
        self.log_entries.push_back(entry);
        
        // Update statistics
        self.statistics.total_entries += 1;
        match level {
            LogLevel::Debug => self.statistics.debug_count += 1,
            LogLevel::Info => self.statistics.info_count += 1,
            LogLevel::Warning => self.statistics.warning_count += 1,
            LogLevel::Error => self.statistics.error_count += 1,
            LogLevel::Critical => self.statistics.critical_count += 1,
        }
        
        if self.auto_scroll {
            self.selected_index = self.filtered_entries().len().saturating_sub(1);
        }
    }
    
    fn filtered_entries(&self) -> Vec<&LogEntry> {
        self.log_entries
            .iter()
            .filter(|entry| entry.level >= self.filter_level)
            .collect()
    }
    
    fn handle_system_event(&mut self, event: &SystemEvent) {
        match event {
            SystemEvent::Startup => {
                self.add_log_entry(LogLevel::Info, "System".to_string(), 
                    "Application started".to_string(), 
                    Some("Synco P2P file synchronization system initialized".to_string()));
            },
            SystemEvent::Shutdown => {
                self.add_log_entry(LogLevel::Info, "System".to_string(), 
                    "Application shutting down".to_string(), None);
            },
            SystemEvent::ModuleLoaded(module) => {
                self.add_log_entry(LogLevel::Info, "ModuleManager".to_string(), 
                    format!("Module '{}' loaded successfully", module), None);
            },
            SystemEvent::ModuleUnloaded(module) => {
                self.add_log_entry(LogLevel::Info, "ModuleManager".to_string(), 
                    format!("Module '{}' unloaded", module), None);
            },
            SystemEvent::ConfigChanged => {
                self.add_log_entry(LogLevel::Warning, "Config".to_string(), 
                    "Configuration changed".to_string(), 
                    Some("System configuration has been updated and reloaded".to_string()));
            },
        }
    }
    
    fn handle_network_event(&mut self, event: &NetworkEvent) {
        match event {
            NetworkEvent::DeviceDiscovered(device) => {
                self.add_log_entry(LogLevel::Info, "Network".to_string(), 
                    format!("Device discovered: {}", device), None);
            },
            NetworkEvent::DeviceConnected(device) => {
                self.add_log_entry(LogLevel::Info, "Network".to_string(), 
                    format!("Connected to device: {}", device), None);
            },
            NetworkEvent::DeviceDisconnected(device) => {
                self.add_log_entry(LogLevel::Warning, "Network".to_string(), 
                    format!("Device disconnected: {}", device), None);
            },
            NetworkEvent::DataReceived { from, data } => {
                self.add_log_entry(LogLevel::Debug, "Network".to_string(), 
                    format!("Received {} bytes from {}", data.len(), from), 
                    Some(format!("Data: {:?}", &data[..std::cmp::min(data.len(), 50)])));
            },
            NetworkEvent::ConnectionError(error) => {
                self.add_log_entry(LogLevel::Error, "Network".to_string(), 
                    format!("Connection error: {}", error), None);
            },
        }
    }
    
    fn handle_filesystem_event(&mut self, event: &FileSystemEvent) {
        match event {
            FileSystemEvent::FileCreated(path) => {
                self.add_log_entry(LogLevel::Info, "FileSystem".to_string(), 
                    format!("File created: {}", path), None);
            },
            FileSystemEvent::FileModified(path) => {
                self.add_log_entry(LogLevel::Debug, "FileSystem".to_string(), 
                    format!("File modified: {}", path), None);
            },
            FileSystemEvent::FileDeleted(path) => {
                self.add_log_entry(LogLevel::Warning, "FileSystem".to_string(), 
                    format!("File deleted: {}", path), None);
            },
            FileSystemEvent::SyncStarted(path) => {
                self.add_log_entry(LogLevel::Info, "Sync".to_string(), 
                    format!("Sync started for: {}", path), None);
            },
            FileSystemEvent::SyncCompleted { path, success } => {
                let level = if *success { LogLevel::Info } else { LogLevel::Error };
                let status = if *success { "completed" } else { "failed" };
                self.add_log_entry(level, "Sync".to_string(), 
                    format!("Sync {} for: {}", status, path), None);
            },
        }
    }
    
    fn cycle_filter(&mut self) {
        self.filter_level = match self.filter_level {
            LogLevel::Debug => LogLevel::Info,
            LogLevel::Info => LogLevel::Warning,
            LogLevel::Warning => LogLevel::Error,
            LogLevel::Error => LogLevel::Critical,
            LogLevel::Critical => LogLevel::Debug,
        };
        self.selected_index = 0;
    }
}

#[async_trait]
impl Module for LogsModule {
    fn id(&self) -> &'static str {
        "logs"
    }
    
    fn priority(&self) -> i32 {
        10 // Low priority, processes events after other modules
    }
    
    async fn init(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError> {
        context.set_state("logs_status", "initialized").await;
        
        self.add_log_entry(LogLevel::Info, "LogsModule".to_string(), 
            "Logs module initialized".to_string(), 
            Some("Ready to capture system events and logs".to_string()));
        
        Ok(())
    }
    
    async fn shutdown(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError> {
        self.add_log_entry(LogLevel::Info, "LogsModule".to_string(), 
            "Logs module shutting down".to_string(), None);
        context.set_state("logs_status", "shutdown").await;
        Ok(())
    }
    
    async fn handle_event(&mut self, event: &ModuleEvent, _context: &mut ModuleContext) -> Result<EventResult, ModuleError> {
        // Log all events that pass through the system
        match event {
            ModuleEvent::System(sys_event) => {
                self.handle_system_event(sys_event);
            },
            ModuleEvent::Network(net_event) => {
                self.handle_network_event(net_event);
            },
            ModuleEvent::FileSystem(fs_event) => {
                self.handle_filesystem_event(fs_event);
            },
            ModuleEvent::UI(ui_event) => {
                match ui_event {
                    UIEvent::TabChanged(tab) => {
                        self.add_log_entry(LogLevel::Debug, "UI".to_string(), 
                            format!("Tab changed to: {}", tab), None);
                    },
                    UIEvent::KeyPressed(key) => {
                        self.add_log_entry(LogLevel::Debug, "UI".to_string(), 
                            format!("Key pressed: {}", key), None);
                    },
                    UIEvent::Refresh => {
                        self.add_log_entry(LogLevel::Debug, "UI".to_string(), 
                            "UI refresh requested".to_string(), None);
                    },
                }
            },
            ModuleEvent::Custom { event_type, data } => {
                self.add_log_entry(LogLevel::Info, "Custom".to_string(), 
                    format!("Custom event: {}", event_type), 
                    Some(format!("Data: {}", data)));
            },
        }
        
        Ok(EventResult::Continue)
    }
    
    fn can_handle(&self, _event: &ModuleEvent) -> bool {
        true // Logs module handles all events for logging purposes
    }
    
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata {
            name: "Logs Module".to_string(),
            version: "1.0.0".to_string(),
            description: "System logging and event tracking".to_string(),
            author: "Synco Team".to_string(),
            dependencies: vec![],
            tags: vec!["logs".to_string(), "monitoring".to_string(), "debug".to_string()],
        }
    }
}

#[async_trait]
impl UIModule for LogsModule {
    fn draw(&self, f: &mut Frame, area: Rect, _context: &ModuleContext) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Statistics bar
                Constraint::Min(6),    // Log entries
                Constraint::Length(3), // Controls
            ])
            .split(area);

        self.draw_statistics(f, chunks[0]);
        
        if self.show_details && !self.filtered_entries().is_empty() {
            self.draw_log_details(f, chunks[1]);
        } else {
            self.draw_log_list(f, chunks[1]);
        }
        
        self.draw_controls(f, chunks[2]);
    }
    
    async fn handle_ui_event(&mut self, event: KeyEvent, context: &mut ModuleContext) -> Result<(), ModuleError> {
        match event.code {
            crossterm::event::KeyCode::Up => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                    self.auto_scroll = false;
                }
            },
            crossterm::event::KeyCode::Down => {
                let filtered = self.filtered_entries();
                if self.selected_index < filtered.len().saturating_sub(1) {
                    self.selected_index += 1;
                }
            },
            crossterm::event::KeyCode::Enter | crossterm::event::KeyCode::Char(' ') => {
                self.show_details = !self.show_details;
            },
            crossterm::event::KeyCode::Char('f') => {
                self.cycle_filter();
            },
            crossterm::event::KeyCode::Char('a') => {
                self.auto_scroll = !self.auto_scroll;
                if self.auto_scroll {
                    self.selected_index = self.filtered_entries().len().saturating_sub(1);
                }
            },
            crossterm::event::KeyCode::Char('c') => {
                // Clear logs
                self.log_entries.clear();
                self.selected_index = 0;
                self.statistics = LogStatistics::default();
                context.emit_event(ModuleEvent::UI(UIEvent::Refresh)).await;
            },
            crossterm::event::KeyCode::Char('t') => {
                // Test log generation
                self.add_log_entry(LogLevel::Info, "Test".to_string(), 
                    "Test log entry generated".to_string(), 
                    Some(format!("Generated at: {:?}", std::time::SystemTime::now())));
            },
            _ => {}
        }
        Ok(())
    }
    
    fn tab_name(&self) -> &'static str {
        "Logs"
    }
}

impl LogsModule {
    fn draw_statistics(&self, f: &mut Frame, area: Rect) {
        let stats_text = format!(
            "Total: {} | Debug: {} | Info: {} | Warn: {} | Error: {} | Critical: {} | Filter: {:?}",
            self.statistics.total_entries,
            self.statistics.debug_count,
            self.statistics.info_count,
            self.statistics.warning_count,
            self.statistics.error_count,
            self.statistics.critical_count,
            self.filter_level
        );
        
        let stats = Paragraph::new(stats_text)
            .style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL).title("Log Statistics"));
        
        f.render_widget(stats, area);
    }
    
    fn draw_log_list(&self, f: &mut Frame, area: Rect) {
        let filtered_entries = self.filtered_entries();
        let logs: Vec<ListItem> = filtered_entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let level_color = match entry.level {
                    LogLevel::Debug => Color::Gray,
                    LogLevel::Info => Color::White,
                    LogLevel::Warning => Color::Yellow,
                    LogLevel::Error => Color::Red,
                    LogLevel::Critical => Color::Magenta,
                };
                
                let level_symbol = match entry.level {
                    LogLevel::Debug => "🐛",
                    LogLevel::Info => "ℹ️",
                    LogLevel::Warning => "⚠️",
                    LogLevel::Error => "❌",
                    LogLevel::Critical => "💥",
                };
                
                let time_str = format!("{:.2}s", 
                    entry.timestamp.elapsed().unwrap_or_default().as_secs_f64());
                
                let style = if i == self.selected_index {
                    Style::default().bg(Color::Blue)
                } else {
                    Style::default()
                };
                
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", level_symbol), Style::default().fg(level_color)),
                    Span::styled(format!("[{}] ", entry.source), Style::default().fg(Color::Cyan)),
                    Span::styled(entry.message.clone(), style.fg(Color::White)),
                    Span::styled(format!(" ({})", time_str), Style::default().fg(Color::Gray)),
                ]))
            })
            .collect();

        let title = format!(
            "System Logs ({}/{}) [↑↓ Navigate | Space Details | f Filter | a AutoScroll: {} | c Clear | t Test]",
            filtered_entries.len(),
            self.log_entries.len(),
            if self.auto_scroll { "ON" } else { "OFF" }
        );

        let log_list = List::new(logs)
            .block(Block::default().title(title).borders(Borders::ALL))
            .style(Style::default().fg(Color::White));

        f.render_widget(log_list, area);
    }
    
    fn draw_log_details(&self, f: &mut Frame, area: Rect) {
        let filtered_entries = self.filtered_entries();
        if let Some(entry) = filtered_entries.get(self.selected_index) {
            let mut details = vec![
                Line::from(format!("Source: {}", entry.source)),
                Line::from(format!("Level: {:?}", entry.level)),
                Line::from(format!("Time: {:?}", entry.timestamp)),
                Line::from(format!("Message: {}", entry.message)),
            ];
            
            if let Some(extra) = &entry.details {
                details.push(Line::from(""));
                details.push(Line::from("Details:"));
                details.push(Line::from(extra.clone()));
            }

            let detail_widget = Paragraph::new(details)
                .block(Block::default().title("Log Details [Space to close]").borders(Borders::ALL))
                .style(Style::default().fg(Color::White))
                .wrap(ratatui::widgets::Wrap { trim: true });

            f.render_widget(Clear, area);
            f.render_widget(detail_widget, area);
        }
    }
    
    fn draw_controls(&self, f: &mut Frame, area: Rect) {
        let controls_text = format!(
            "Controls: [f] Filter: {:?} | [a] Auto-scroll: {} | [c] Clear | [t] Test entry",
            self.filter_level,
            if self.auto_scroll { "ON" } else { "OFF" }
        );
        
        let controls = Paragraph::new(controls_text)
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL).title("Controls"));
        
        f.render_widget(controls, area);
    }
}

// Legacy function for backwards compatibility
pub fn draw(f: &mut Frame, area: Rect) {
    let mut module = LogsModule::new();
    module.add_log_entry(LogLevel::Info, "System".to_string(), 
        "Application started".to_string(), None);
    
    let context = crate::chain::ModuleContext::new(crate::chain::ModuleConfig {
        enabled_modules: vec!["logs".to_string()],
        module_settings: std::collections::HashMap::new(),
    });
    
    module.draw(f, area, &context);
}
