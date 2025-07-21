use crate::chain::{UIModule, Module, ModuleContext, ModuleEvent, EventResult, ModuleError, ModuleMetadata, FileSystemEvent, UIEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Modifier},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Table, Row, Cell, Clear},
};
use async_trait::async_trait;
use crossterm::event::KeyEvent;
use std::collections::HashMap;

pub struct FilesModule {
    synchronized_files: Vec<SyncFile>,
    recent_operations: Vec<FileOperation>,
    selected_index: usize,
    show_details: bool,
    sync_stats: SyncStats,
}

#[derive(Clone, Debug)]
struct SyncFile {
    path: String,
    size: u64,
    status: SyncStatus,
    last_modified: std::time::SystemTime,
    sync_progress: f64,
    checksum: String,
}

#[derive(Clone, Debug)]
enum SyncStatus {
    Synced,
    Syncing,
    Conflict,
    Error(String),
    Pending,
}

#[derive(Clone, Debug)]
struct FileOperation {
    operation_type: String,
    path: String,
    timestamp: std::time::SystemTime,
    status: String,
}

#[derive(Clone, Debug, Default)]
struct SyncStats {
    total_files: usize,
    synced_files: usize,
    pending_files: usize,
    failed_files: usize,
    total_size: u64,
    synced_size: u64,
}

impl FilesModule {
    pub fn new() -> Self {
        Self {
            synchronized_files: Vec::new(),
            recent_operations: Vec::new(),
            selected_index: 0,
            show_details: false,
            sync_stats: SyncStats::default(),
        }
    }

    fn update_file_event(&mut self, event: &FileSystemEvent) {
        match event {
            FileSystemEvent::FileCreated(path) => {
                let file = SyncFile {
                    path: path.clone(),
                    size: 0, // TODO: Get actual size
                    status: SyncStatus::Pending,
                    last_modified: std::time::SystemTime::now(),
                    sync_progress: 0.0,
                    checksum: "".to_string(),
                };
                self.synchronized_files.push(file);
                
                self.recent_operations.push(FileOperation {
                    operation_type: "Created".to_string(),
                    path: path.clone(),
                    timestamp: std::time::SystemTime::now(),
                    status: "Success".to_string(),
                });
            },
            FileSystemEvent::SyncStarted(path) => {
                if let Some(file) = self.synchronized_files.iter_mut().find(|f| f.path == *path) {
                    file.status = SyncStatus::Syncing;
                    file.sync_progress = 0.0;
                }
            },
            FileSystemEvent::SyncCompleted { path, success } => {
                if let Some(file) = self.synchronized_files.iter_mut().find(|f| f.path == *path) {
                    file.status = if *success { SyncStatus::Synced } else { SyncStatus::Error("Sync failed".to_string()) };
                    file.sync_progress = if *success { 100.0 } else { 0.0 };
                }
                
                self.recent_operations.push(FileOperation {
                    operation_type: "Sync".to_string(),
                    path: path.clone(),
                    timestamp: std::time::SystemTime::now(),
                    status: if *success { "Success".to_string() } else { "Failed".to_string() },
                });
            },
            _ => {}
        }
        
        self.update_stats();
    }
    
    fn update_stats(&mut self) {
        self.sync_stats.total_files = self.synchronized_files.len();
        self.sync_stats.synced_files = self.synchronized_files.iter().filter(|f| matches!(f.status, SyncStatus::Synced)).count();
        self.sync_stats.pending_files = self.synchronized_files.iter().filter(|f| matches!(f.status, SyncStatus::Pending)).count();
        self.sync_stats.failed_files = self.synchronized_files.iter().filter(|f| matches!(f.status, SyncStatus::Error(_))).count();
        self.sync_stats.total_size = self.synchronized_files.iter().map(|f| f.size).sum();
        self.sync_stats.synced_size = self.synchronized_files.iter()
            .filter(|f| matches!(f.status, SyncStatus::Synced))
            .map(|f| f.size)
            .sum();
    }
}

#[async_trait]
impl Module for FilesModule {
    fn id(&self) -> &'static str {
        "files"
    }
    
    fn priority(&self) -> i32 {
        60
    }
    
    async fn init(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError> {
        context.set_state("files_status", "initialized").await;
        
        // Добавляем некоторые тестовые файлы
        self.synchronized_files.push(SyncFile {
            path: "/home/user/documents/readme.txt".to_string(),
            size: 1024,
            status: SyncStatus::Synced,
            last_modified: std::time::SystemTime::now(),
            sync_progress: 100.0,
            checksum: "abc123".to_string(),
        });
        
        self.synchronized_files.push(SyncFile {
            path: "/home/user/projects/main.rs".to_string(),
            size: 4096,
            status: SyncStatus::Syncing,
            last_modified: std::time::SystemTime::now(),
            sync_progress: 65.0,
            checksum: "def456".to_string(),
        });
        
        self.update_stats();
        Ok(())
    }
    
    async fn shutdown(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError> {
        context.set_state("files_status", "shutdown").await;
        Ok(())
    }
    
    async fn handle_event(&mut self, event: &ModuleEvent, context: &mut ModuleContext) -> Result<EventResult, ModuleError> {
        match event {
            ModuleEvent::FileSystem(fs_event) => {
                self.update_file_event(fs_event);
                context.emit_event(ModuleEvent::UI(UIEvent::Refresh)).await;
                Ok(EventResult::Continue)
            },
            _ => Ok(EventResult::Continue)
        }
    }
    
    fn can_handle(&self, event: &ModuleEvent) -> bool {
        matches!(event, ModuleEvent::FileSystem(_))
    }
    
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata {
            name: "Files Module".to_string(),
            version: "1.0.0".to_string(),
            description: "Manages file synchronization and operations".to_string(),
            author: "Synco Team".to_string(),
            dependencies: vec!["filesystem".to_string()],
            tags: vec!["files".to_string(), "sync".to_string()],
        }
    }
}

#[async_trait]
impl UIModule for FilesModule {
    fn draw(&self, f: &mut Frame, area: Rect, context: &ModuleContext) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Stats bar
                Constraint::Min(8),    // File list
                Constraint::Length(6), // Operations
            ])
            .split(area);

        self.draw_stats_bar(f, chunks[0]);
        
        if self.show_details && !self.synchronized_files.is_empty() {
            self.draw_file_details(f, chunks[1]);
        } else {
            self.draw_file_list(f, chunks[1]);
        }
        
        self.draw_operations(f, chunks[2]);
    }
    
    async fn handle_ui_event(&mut self, event: KeyEvent, context: &mut ModuleContext) -> Result<(), ModuleError> {
        match event.code {
            crossterm::event::KeyCode::Up => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                }
            },
            crossterm::event::KeyCode::Down => {
                if self.selected_index < self.synchronized_files.len().saturating_sub(1) {
                    self.selected_index += 1;
                }
            },
            crossterm::event::KeyCode::Enter | crossterm::event::KeyCode::Char(' ') => {
                self.show_details = !self.show_details;
            },
            crossterm::event::KeyCode::Char('s') => {
                // Trigger sync for selected file
                if let Some(file) = self.synchronized_files.get(self.selected_index) {
                    context.emit_event(ModuleEvent::FileSystem(FileSystemEvent::SyncStarted(
                        file.path.clone()
                    ))).await;
                }
            },
            crossterm::event::KeyCode::Char('a') => {
                // Add new file simulation
                context.emit_event(ModuleEvent::FileSystem(FileSystemEvent::FileCreated(
                    format!("/tmp/new_file_{}.txt", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs())
                ))).await;
            },
            _ => {}
        }
        Ok(())
    }
    
    fn tab_name(&self) -> &'static str {
        "Files"
    }
}

impl FilesModule {
    fn draw_stats_bar(&self, f: &mut Frame, area: Rect) {
        let stats_text = format!(
            "Total: {} | Synced: {} | Pending: {} | Failed: {} | Size: {:.1} MB",
            self.sync_stats.total_files,
            self.sync_stats.synced_files,
            self.sync_stats.pending_files,
            self.sync_stats.failed_files,
            self.sync_stats.total_size as f64 / 1024.0 / 1024.0
        );
        
        let stats = Paragraph::new(stats_text)
            .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL).title("File Statistics"));
        
        f.render_widget(stats, area);
    }
    
    fn draw_file_list(&self, f: &mut Frame, area: Rect) {
        let files: Vec<ListItem> = self.synchronized_files
            .iter()
            .enumerate()
            .map(|(i, file)| {
                let status_color = match &file.status {
                    SyncStatus::Synced => Color::Green,
                    SyncStatus::Syncing => Color::Yellow,
                    SyncStatus::Conflict => Color::Magenta,
                    SyncStatus::Error(_) => Color::Red,
                    SyncStatus::Pending => Color::Gray,
                };
                
                let status_symbol = match &file.status {
                    SyncStatus::Synced => "✓",
                    SyncStatus::Syncing => "↻",
                    SyncStatus::Conflict => "⚠",
                    SyncStatus::Error(_) => "✗",
                    SyncStatus::Pending => "⏳",
                };
                
                let style = if i == self.selected_index {
                    Style::default().bg(Color::Blue)
                } else {
                    Style::default()
                };
                
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", status_symbol), Style::default().fg(status_color)),
                    Span::styled(
                        format!("{} ", file.path.split('/').last().unwrap_or(&file.path)),
                        style.fg(Color::White)
                    ),
                    Span::styled(
                        format!("({:.1} KB)", file.size as f64 / 1024.0),
                        Style::default().fg(Color::Gray)
                    ),
                ]))
            })
            .collect();

        let file_list = List::new(files)
            .block(
                Block::default()
                    .title("Synchronized Files [↑↓ Navigate | Space/Enter Details | s Sync | a Add]")
                    .borders(Borders::ALL),
            )
            .style(Style::default().fg(Color::White));

        f.render_widget(file_list, area);
    }
    
    fn draw_file_details(&self, f: &mut Frame, area: Rect) {
        if let Some(file) = self.synchronized_files.get(self.selected_index) {
            let details = vec![
                Row::new(vec![Cell::from("Path:"), Cell::from(file.path.clone())]),
                Row::new(vec![Cell::from("Size:"), Cell::from(format!("{} bytes", file.size))]),
                Row::new(vec![Cell::from("Status:"), Cell::from(format!("{:?}", file.status))]),
                Row::new(vec![Cell::from("Progress:"), Cell::from(format!("{:.1}%", file.sync_progress))]),
                Row::new(vec![Cell::from("Checksum:"), Cell::from(file.checksum.clone())]),
                Row::new(vec![Cell::from("Modified:"), Cell::from("Recently")]), // TODO: format timestamp
            ];

            let table = Table::new(details, [Constraint::Length(12), Constraint::Min(20)])
                .block(Block::default().title("File Details [Space to close]").borders(Borders::ALL))
                .style(Style::default().fg(Color::White));

            f.render_widget(Clear, area);
            f.render_widget(table, area);
        }
    }
    
    fn draw_operations(&self, f: &mut Frame, area: Rect) {
        let operations: Vec<Line> = self.recent_operations
            .iter()
            .rev()
            .take(4)
            .map(|op| {
                let status_color = match op.status.as_str() {
                    "Success" => Color::Green,
                    "Failed" => Color::Red,
                    _ => Color::Yellow,
                };
                
                Line::from(vec![
                    Span::styled(format!("{}: ", op.operation_type), Style::default().fg(Color::Cyan)),
                    Span::styled(
                        op.path.split('/').last().unwrap_or(&op.path),
                        Style::default().fg(Color::White)
                    ),
                    Span::styled(format!(" ({})", op.status), Style::default().fg(status_color)),
                ])
            })
            .collect();

        let operations_widget = Paragraph::new(operations)
            .block(
                Block::default()
                    .title("Recent Operations")
                    .borders(Borders::ALL),
            )
            .style(Style::default().fg(Color::White));

        f.render_widget(operations_widget, area);
    }
}

// Legacy function for backwards compatibility
pub fn draw(f: &mut Frame, area: Rect) {
    let module = FilesModule::new();
    let context = crate::chain::ModuleContext::new(crate::chain::ModuleConfig {
        enabled_modules: vec!["files".to_string()],
        module_settings: std::collections::HashMap::new(),
    });
    module.draw(f, area, &context);
}
