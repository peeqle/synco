use crate::ui::chain::{UIModule, Module, ModuleContext, ModuleEvent, EventResult, ModuleError, ModuleMetadata, NetworkEvent, UIEvent};
use crate::consts::{DEFAULT_LISTENING_PORT, DEFAULT_SERVER_PORT};
use crate::device_manager::DefaultDeviceManager;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Modifier},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Gauge},
};
use std::sync::Arc;
use async_trait::async_trait;
use crossterm::event::KeyEvent;

pub struct NetworkModule {
    connected_devices: Vec<String>,
    connection_status: String,
    last_activity: Option<std::time::Instant>,
    bytes_sent: u64,
    bytes_received: u64,
}

impl NetworkModule {
    pub fn new() -> Self {
        Self {
            connected_devices: Vec::new(),
            connection_status: "Disconnected".to_string(),
            last_activity: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
    
    fn update_stats(&mut self, event: &NetworkEvent) {
        match event {
            NetworkEvent::DeviceConnected(device) => {
                if !self.connected_devices.contains(device) {
                    self.connected_devices.push(device.clone());
                }
                self.connection_status = format!("{} devices connected", self.connected_devices.len());
            },
            NetworkEvent::DeviceDisconnected(device) => {
                self.connected_devices.retain(|d| d != device);
                self.connection_status = if self.connected_devices.is_empty() {
                    "Disconnected".to_string()
                } else {
                    format!("{} devices connected", self.connected_devices.len())
                };
            },
            NetworkEvent::DataReceived { from: _, data } => {
                self.bytes_received += data.len() as u64;
                self.last_activity = Some(std::time::Instant::now());
            },
            _ => {}
        }
    }
}

#[async_trait]
impl Module for NetworkModule {
    fn id(&self) -> &'static str {
        "network"
    }
    
    fn priority(&self) -> i32 {
        50 // Высокий приоритет для сетевых событий
    }
    
    async fn init(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError> {
        // Инициализация сетевого модуля
        context.set_state("network_status", "initializing").await;
        
        // Подписываемся на сетевые события
        let event_bus = Arc::clone(&context.event_bus);
        event_bus.subscribe("network", |event| {
            if let ModuleEvent::Network(net_event) = event {
                println!("Network event received: {:?}", net_event);
            }
        }).await;
        
        context.set_state("network_status", "initialized").await;
        Ok(())
    }
    
    async fn shutdown(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError> {
        context.set_state("network_status", "shutdown").await;
        Ok(())
    }
    
    async fn handle_event(&mut self, event: &ModuleEvent, context: &mut ModuleContext) -> Result<EventResult, ModuleError> {
        match event {
            ModuleEvent::Network(net_event) => {
                self.update_stats(net_event);
                
                // Уведомляем о изменении состояния
                context.emit_event(ModuleEvent::UI(UIEvent::Refresh)).await;
                
                Ok(EventResult::Continue)
            },
            ModuleEvent::System(crate::ui::chain::SystemEvent::Startup) => {
                // Запускаем обнаружение устройств
                context.emit_event(ModuleEvent::Network(NetworkEvent::DeviceDiscovered(
                    "localhost".to_string()
                ))).await;
                Ok(EventResult::Continue)
            },
            _ => Ok(EventResult::Continue)
        }
    }
    
    fn can_handle(&self, event: &ModuleEvent) -> bool {
        matches!(event, ModuleEvent::Network(_) | ModuleEvent::System(_))
    }
    
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata {
            name: "Network Module".to_string(),
            version: "1.0.0".to_string(),
            description: "Handles P2P network connections and device discovery".to_string(),
            author: "Synco Team".to_string(),
            dependencies: vec!["device_manager".to_string()],
            tags: vec!["network".to_string(), "p2p".to_string()],
        }
    }
}

#[async_trait]
impl UIModule for NetworkModule {
    fn draw(&self, f: &mut Frame, area: Rect, context: &ModuleContext) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Status bar
                Constraint::Min(8),    // Main content
                Constraint::Length(3), // Stats bar
            ])
            .split(area);

        self.draw_status_bar(f, chunks[0]);
        
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[1]);
        
        self.draw_device_list(f, main_chunks[0]);
        self.draw_network_info(f, main_chunks[1]);
        self.draw_stats_bar(f, chunks[2]);
    }
    
    async fn handle_ui_event(&mut self, event: KeyEvent, context: &mut ModuleContext) -> Result<(), ModuleError> {
        match event.code {
            crossterm::event::KeyCode::Char('r') => {
                // Refresh network
                context.emit_event(ModuleEvent::Network(NetworkEvent::DeviceDiscovered(
                    format!("device_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs())
                ))).await;
            },
            crossterm::event::KeyCode::Char('c') => {
                // Clear connections
                self.connected_devices.clear();
                self.connection_status = "Disconnected".to_string();
                context.emit_event(ModuleEvent::UI(UIEvent::Refresh)).await;
            },
            _ => {}
        }
        Ok(())
    }
    
    fn tab_name(&self) -> &'static str {
        "Network"
    }
}

impl NetworkModule {
    fn draw_status_bar(&self, f: &mut Frame, area: Rect) {
        let status_text = format!(
            "Status: {} | Devices: {} | Last Activity: {}",
            self.connection_status,
            self.connected_devices.len(),
            self.last_activity
                .map(|t| format!("{:.1}s ago", t.elapsed().as_secs_f32()))
                .unwrap_or_else(|| "Never".to_string())
        );
        
        let status = Paragraph::new(status_text)
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL).title("Network Status"));
        
        f.render_widget(status, area);
    }
    
    fn draw_device_list(&self, f: &mut Frame, area: Rect) {
        let devices: Vec<ListItem> = self.connected_devices
            .iter()
            .enumerate()
            .map(|(i, device)| {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("[{}] ", i + 1),
                        Style::default().fg(Color::Yellow)
                    ),
                    Span::styled(
                        device.clone(),
                        Style::default().fg(Color::White)
                    ),
                    Span::styled(
                        " ●",
                        Style::default().fg(Color::Green)
                    ),
                ]))
            })
            .collect();

        let device_list = List::new(devices)
            .block(
                Block::default()
                    .title("Connected Devices")
                    .borders(Borders::ALL),
            )
            .style(Style::default().fg(Color::White));

        f.render_widget(device_list, area);
    }
    
    fn draw_network_info(&self, f: &mut Frame, area: Rect) {
        let info_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6), // Connection info
                Constraint::Min(4),    // Network settings
            ])
            .split(area);
        
        // Connection information
        let connection_info = vec![
            Line::from("Network Configuration:"),
            Line::from(format!("Listening Port: {}", DEFAULT_LISTENING_PORT)),
            Line::from(format!("Server Port: {}", DEFAULT_SERVER_PORT)),
            Line::from("Protocol: P2P Direct Connection"),
        ];

        let connection_widget = Paragraph::new(connection_info)
            .block(
                Block::default()
                    .title("Connection Info")
                    .borders(Borders::ALL),
            )
            .style(Style::default().fg(Color::White));

        f.render_widget(connection_widget, info_chunks[0]);
        
        // Network settings/actions
        let settings_info = vec![
            Line::from("Available Actions:"),
            Line::from("[r] Refresh network"),
            Line::from("[c] Clear connections"),
            Line::from("[d] Discover devices"),
        ];
        
        let settings_widget = Paragraph::new(settings_info)
            .block(
                Block::default()
                    .title("Controls")
                    .borders(Borders::ALL),
            )
            .style(Style::default().fg(Color::Gray));

        f.render_widget(settings_widget, info_chunks[1]);
    }
    
    fn draw_stats_bar(&self, f: &mut Frame, area: Rect) {
        let stats_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        
        // Bytes sent gauge
        let sent_ratio = (self.bytes_sent as f64 / 1024.0 / 1024.0).min(100.0) / 100.0;
        let sent_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Data Sent (MB)"))
            .gauge_style(Style::default().fg(Color::Blue))
            .ratio(sent_ratio)
            .label(format!("{:.2} MB", self.bytes_sent as f64 / 1024.0 / 1024.0));
        
        f.render_widget(sent_gauge, stats_chunks[0]);
        
        // Bytes received gauge  
        let received_ratio = (self.bytes_received as f64 / 1024.0 / 1024.0).min(100.0) / 100.0;
        let received_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Data Received (MB)"))
            .gauge_style(Style::default().fg(Color::Green))
            .ratio(received_ratio)
            .label(format!("{:.2} MB", self.bytes_received as f64 / 1024.0 / 1024.0));
        
        f.render_widget(received_gauge, stats_chunks[1]);
    }
}

// Legacy function for backwards compatibility
pub fn draw(f: &mut Frame, area: Rect) {
    let module = NetworkModule::new();
    let context = crate::ui::chain::ModuleContext::new(crate::ui::chain::ModuleConfig {
        enabled_modules: vec!["network".to_string()],
        module_settings: std::collections::HashMap::new(),
    });
    module.draw(f, area, &context);
}
