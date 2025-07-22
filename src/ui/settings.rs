use crate::ui::chain::{EventResult, Module, ModuleContext, ModuleError, ModuleEvent, ModuleMetadata, SystemEvent, UIEvent, UIModule};
use async_trait::async_trait;
use crossterm::event::KeyEvent;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Frame,
};
use std::collections::HashMap;

pub struct SettingsModule {
    settings: HashMap<String, SettingValue>,
    selected_index: usize,
    in_edit_mode: bool,
    module_stats: ModuleStatistics,
}

#[derive(Clone, Debug)]
enum SettingValue {
    Bool(bool),
    String(String),
    Number(f64),
    Port(u16),
}

#[derive(Clone, Debug, Default)]
struct ModuleStatistics {
    active_modules: usize,
    total_events_processed: u64,
    average_response_time_ms: f64,
    memory_usage_mb: f64,
}

impl SettingsModule {
    pub fn new() -> Self {
        let mut settings = HashMap::new();

        // Default application settings
        settings.insert("auto_connect".to_string(), SettingValue::Bool(true));
        settings.insert("max_connections".to_string(), SettingValue::Number(10.0));
        settings.insert("buffer_size_kb".to_string(), SettingValue::Number(1024.0));
        settings.insert("listening_port".to_string(), SettingValue::Port(8080));
        settings.insert("device_name".to_string(), SettingValue::String("Synco-Device".to_string()));
        settings.insert("auto_sync".to_string(), SettingValue::Bool(true));
        settings.insert("compression_enabled".to_string(), SettingValue::Bool(true));
        settings.insert("encryption_level".to_string(), SettingValue::String("AES-256".to_string()));
        settings.insert("sync_interval_sec".to_string(), SettingValue::Number(30.0));
        settings.insert("verbose_logging".to_string(), SettingValue::Bool(false));

        Self {
            settings,
            selected_index: 0,
            in_edit_mode: false,
            module_stats: ModuleStatistics::default(),
        }
    }

    fn get_setting_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.settings.keys().cloned().collect();
        keys.sort();
        keys
    }

    fn toggle_boolean_setting(&mut self, key: &str) {
        if let Some(SettingValue::Bool(value)) = self.settings.get_mut(key) {
            *value = !*value;
        }
    }

    fn update_module_stats(&mut self, context: &ModuleContext) {
        // In a real implementation, these would come from the actual system state
        self.module_stats.active_modules = 4; // NetworkModule, FilesModule, LogsModule, PerformanceModule
        self.module_stats.total_events_processed += 1;
        self.module_stats.average_response_time_ms = 2.5; // Simulated
        self.module_stats.memory_usage_mb = 45.2; // Simulated
    }

    fn get_setting_description(&self, key: &str) -> &'static str {
        match key {
            "auto_connect" => "Automatically connect to discovered devices",
            "max_connections" => "Maximum number of simultaneous connections",
            "buffer_size_kb" => "Network buffer size in kilobytes",
            "listening_port" => "Port to listen for incoming connections",
            "device_name" => "Name of this device on the network",
            "auto_sync" => "Enable automatic file synchronization",
            "compression_enabled" => "Use compression for file transfers",
            "encryption_level" => "Encryption algorithm for secure transfers",
            "sync_interval_sec" => "Interval between sync checks in seconds",
            "verbose_logging" => "Enable detailed debug logging",
            _ => "Configuration setting",
        }
    }
}

#[async_trait]
impl Module for SettingsModule {
    fn id(&self) -> &'static str {
        "settings"
    }

    fn priority(&self) -> i32 {
        90 // Low priority utility module
    }

    async fn init(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError> {
        context.set_state("settings_status", "initialized").await;

        // Load settings from configuration if available
        if let Some(config_settings) = context.config.module_settings.get("settings") {
            // In a real implementation, we'd deserialize and apply saved settings
            context.set_state("settings_loaded", true).await;
        }

        Ok(())
    }

    async fn shutdown(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError> {
        context.set_state("settings_status", "shutdown").await;

        // Save current settings to persistent storage
        context.set_state("settings_saved", true).await;

        Ok(())
    }

    async fn handle_event(&mut self, event: &ModuleEvent, context: &mut ModuleContext) -> Result<EventResult, ModuleError> {
        // Update statistics on every event
        self.update_module_stats(context);

        match event {
            ModuleEvent::System(SystemEvent::ConfigChanged) => {
                context.emit_event(ModuleEvent::UI(UIEvent::Refresh)).await;
                Ok(EventResult::Continue)
            }
            ModuleEvent::Custom { event_type, data } if event_type == "setting_changed" => {
                // Handle setting changes from other modules
                if let Some(setting_name) = data.get("name") {
                    if let Some(setting_value) = data.get("value") {
                        // Update the setting based on the event
                        // This is a simplified example
                    }
                }
                Ok(EventResult::Continue)
            }
            _ => Ok(EventResult::Continue)
        }
    }

    fn can_handle(&self, event: &ModuleEvent) -> bool {
        match event {
            ModuleEvent::System(sys_event) => {
                matches!(sys_event, SystemEvent::ConfigChanged)
            },
            ModuleEvent::Custom { event_type, .. } => {
                event_type == "setting_changed"
            },
            _ => false,
        }
    }

    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata {
            name: "Settings Module".to_string(),
            version: "1.0.0".to_string(),
            description: "Application configuration and system settings management".to_string(),
            author: "Synco Team".to_string(),
            dependencies: vec!["config".to_string()],
            tags: vec!["settings".to_string(), "config".to_string(), "management".to_string()],
        }
    }
}

#[async_trait]
impl UIModule for SettingsModule {
    fn draw(&self, f: &mut Frame, area: Rect, context: &ModuleContext) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),  // Module statistics
                Constraint::Min(10),    // Settings list
                Constraint::Length(4),  // Help/Controls
            ])
            .split(area);

        self.draw_module_stats(f, chunks[0]);
        self.draw_settings_list(f, chunks[1]);
        self.draw_controls(f, chunks[2]);
    }

    async fn handle_ui_event(&mut self, event: KeyEvent, context: &mut ModuleContext) -> Result<(), ModuleError> {
        match event.code {
            crossterm::event::KeyCode::Up => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                }
            }
            crossterm::event::KeyCode::Down => {
                let keys = self.get_setting_keys();
                if self.selected_index < keys.len().saturating_sub(1) {
                    self.selected_index += 1;
                }
            }
            crossterm::event::KeyCode::Enter | crossterm::event::KeyCode::Char(' ') => {
                let keys = self.get_setting_keys();
                if let Some(key) = keys.get(self.selected_index) {
                    self.toggle_boolean_setting(key);

                    // Emit configuration change event
                    context.emit_event(ModuleEvent::System(SystemEvent::ConfigChanged)).await;
                    context.emit_event(ModuleEvent::Custom {
                        event_type: "setting_changed".to_string(),
                        data: serde_json::json!({
                            "name": key,
                            "value": format!("{:?}", self.settings.get(key))
                        }),
                    }).await;
                }
            }
            crossterm::event::KeyCode::Char('r') => {
                // Reset all settings to defaults
                *self = Self::new();
                context.emit_event(ModuleEvent::System(SystemEvent::ConfigChanged)).await;
            }
            crossterm::event::KeyCode::Char('s') => {
                // Save settings (simulate)
                context.set_state("last_settings_save", std::time::SystemTime::now()).await;
                context.emit_event(ModuleEvent::UI(UIEvent::Refresh)).await;
            }
            _ => {}
        }
        Ok(())
    }

    fn tab_name(&self) -> &'static str {
        "Settings"
    }
}

impl SettingsModule {
    fn draw_module_stats(&self, f: &mut Frame, area: Rect) {
        let stats_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Left side - module info
        let module_info = vec![
            Line::from(vec![
                Span::styled("Active Modules: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", self.module_stats.active_modules), Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("Events Processed: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", self.module_stats.total_events_processed), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Avg Response: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{:.1}ms", self.module_stats.average_response_time_ms), Style::default().fg(Color::Yellow)),
            ]),
        ];

        let info_widget = Paragraph::new(module_info)
            .block(Block::default().title("Module Statistics").borders(Borders::ALL))
            .style(Style::default().fg(Color::White));
        f.render_widget(info_widget, stats_chunks[0]);

        // Right side - memory usage gauge
        let memory_ratio = (self.module_stats.memory_usage_mb / 100.0).min(1.0);
        let memory_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Memory Usage"))
            .gauge_style(Style::default().fg(
                if memory_ratio > 0.8 { Color::Red } else if memory_ratio > 0.6 { Color::Yellow } else { Color::Green }
            ))
            .ratio(memory_ratio)
            .label(format!("{:.1} MB", self.module_stats.memory_usage_mb));
        f.render_widget(memory_gauge, stats_chunks[1]);
    }

    fn draw_settings_list(&self, f: &mut Frame, area: Rect) {
        let keys = self.get_setting_keys();
        let settings_items: Vec<ListItem> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let value = self.settings.get(key).unwrap();
                let value_str = match value {
                    SettingValue::Bool(b) => {
                        if *b { "✓ Enabled".to_string() } else { "✗ Disabled".to_string() }
                    }
                    SettingValue::String(s) => s.clone(),
                    SettingValue::Number(n) => format!("{:.1}", n),
                    SettingValue::Port(p) => format!("{}", p),
                };

                let description = self.get_setting_description(key);

                let style = if i == self.selected_index {
                    Style::default().bg(Color::Blue)
                } else {
                    Style::default()
                };

                let value_color = match value {
                    SettingValue::Bool(true) => Color::Green,
                    SettingValue::Bool(false) => Color::Red,
                    _ => Color::Cyan,
                };

                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(format!("{}: ", key), style.fg(Color::White)),
                        Span::styled(value_str, style.fg(value_color)),
                    ]),
                    Line::from(Span::styled(format!("  {}", description), Style::default().fg(Color::Gray))),
                ])
            })
            .collect();

        let settings_list = List::new(settings_items)
            .block(
                Block::default()
                    .title("Application Settings [↑↓ Navigate | Space/Enter Toggle | r Reset | s Save]")
                    .borders(Borders::ALL),
            )
            .style(Style::default().fg(Color::White));

        f.render_widget(settings_list, area);
    }

    fn draw_controls(&self, f: &mut Frame, area: Rect) {
        let controls_lines = vec![
            Line::from("Controls:"),
            Line::from(vec![
                Span::styled("[↑↓] ", Style::default().fg(Color::Yellow)),
                Span::styled("Navigate ", Style::default().fg(Color::White)),
                Span::styled("[Space/Enter] ", Style::default().fg(Color::Yellow)),
                Span::styled("Toggle ", Style::default().fg(Color::White)),
                Span::styled("[r] ", Style::default().fg(Color::Yellow)),
                Span::styled("Reset ", Style::default().fg(Color::White)),
                Span::styled("[s] ", Style::default().fg(Color::Yellow)),
                Span::styled("Save", Style::default().fg(Color::White)),
            ]),
        ];

        let controls = Paragraph::new(controls_lines)
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL).title("Help"));

        f.render_widget(controls, area);
    }
} 