use crate::chain::{UIModule, Module, ModuleContext, ModuleEvent, EventResult, ModuleError, ModuleMetadata, SystemEvent, UIEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Modifier},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Gauge, Chart, Axis, Dataset, GraphType},
};
use async_trait::async_trait;
use crossterm::event::KeyEvent;
use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct PerformanceModule {
    // System metrics
    cpu_usage: VecDeque<(f64, f64)>, // (timestamp, cpu_percentage)
    memory_usage: VecDeque<(f64, f64)>, // (timestamp, memory_mb)
    network_throughput: VecDeque<(f64, f64)>, // (timestamp, bytes_per_second)
    
    // Performance counters
    events_processed: u64,
    events_per_second: f64,
    avg_event_processing_time: Duration,
    
    // Runtime info
    app_start_time: Instant,
    last_update: Instant,
    update_interval: Duration,
    
    // UI state
    selected_metric: usize,
    time_window_minutes: f64,
}

impl PerformanceModule {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            cpu_usage: VecDeque::with_capacity(1000),
            memory_usage: VecDeque::with_capacity(1000),
            network_throughput: VecDeque::with_capacity(1000),
            events_processed: 0,
            events_per_second: 0.0,
            avg_event_processing_time: Duration::from_millis(0),
            app_start_time: now,
            last_update: now,
            update_interval: Duration::from_secs(1),
            selected_metric: 0,
            time_window_minutes: 5.0,
        }
    }
    
    fn update_metrics(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_update) < self.update_interval {
            return;
        }
        
        let timestamp = now.duration_since(self.app_start_time).as_secs_f64();
        
        // Simulate CPU usage (in a real implementation, you'd use system calls)
        let cpu_usage = Self::simulate_cpu_usage();
        self.cpu_usage.push_back((timestamp, cpu_usage));
        
        // Simulate memory usage
        let memory_usage = Self::simulate_memory_usage();
        self.memory_usage.push_back((timestamp, memory_usage));
        
        // Calculate network throughput (simulation)
        let network_throughput = Self::simulate_network_throughput();
        self.network_throughput.push_back((timestamp, network_throughput));
        
        // Keep only data within time window
        let cutoff_time = timestamp - (self.time_window_minutes * 60.0);
        self.cpu_usage.retain(|(t, _)| *t >= cutoff_time);
        self.memory_usage.retain(|(t, _)| *t >= cutoff_time);
        self.network_throughput.retain(|(t, _)| *t >= cutoff_time);
        
        self.last_update = now;
    }
    
    fn simulate_cpu_usage() -> f64 {
        // Simulate varying CPU usage between 10-80%
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
        let random = (hasher.finish() % 100) as f64;
        
        20.0 + (random * 0.6).sin().abs() * 60.0
    }
    
    fn simulate_memory_usage() -> f64 {
        // Simulate memory usage between 50-500MB
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() + 12345).hash(&mut hasher);
        let random = (hasher.finish() % 1000) as f64;
        
        50.0 + random * 0.45
    }
    
    fn simulate_network_throughput() -> f64 {
        // Simulate network throughput in KB/s
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() + 54321).hash(&mut hasher);
        let random = (hasher.finish() % 100) as f64;
        
        random * 10.0 // 0-1000 KB/s
    }
    
    fn get_current_metrics(&self) -> (f64, f64, f64) {
        let cpu = self.cpu_usage.back().map(|(_, cpu)| *cpu).unwrap_or(0.0);
        let memory = self.memory_usage.back().map(|(_, mem)| *mem).unwrap_or(0.0);
        let network = self.network_throughput.back().map(|(_, net)| *net).unwrap_or(0.0);
        (cpu, memory, network)
    }
    
    fn get_uptime(&self) -> Duration {
        self.last_update.duration_since(self.app_start_time)
    }
    
    fn cycle_metric(&mut self) {
        self.selected_metric = (self.selected_metric + 1) % 3;
    }
    
    fn cycle_time_window(&mut self) {
        match self.time_window_minutes as i32 {
            1 => self.time_window_minutes = 5.0,
            5 => self.time_window_minutes = 15.0,
            15 => self.time_window_minutes = 30.0,
            30 => self.time_window_minutes = 60.0,
            _ => self.time_window_minutes = 1.0,
        }
    }
}

#[async_trait]
impl Module for PerformanceModule {
    fn id(&self) -> &'static str {
        "performance"
    }
    
    fn priority(&self) -> i32 {
        80 // Lower priority than core modules
    }
    
    async fn init(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError> {
        context.set_state("performance_status", "initialized").await;
        Ok(())
    }
    
    async fn shutdown(&mut self, context: &mut ModuleContext) -> Result<(), ModuleError> {
        context.set_state("performance_status", "shutdown").await;
        Ok(())
    }
    
    async fn handle_event(&mut self, event: &ModuleEvent, _context: &mut ModuleContext) -> Result<EventResult, ModuleError> {
        // Count processed events
        self.events_processed += 1;
        
        // Update metrics periodically
        self.update_metrics();
        
        // Calculate events per second
        let uptime = self.get_uptime();
        if uptime.as_secs() > 0 {
            self.events_per_second = self.events_processed as f64 / uptime.as_secs_f64();
        }
        
        Ok(EventResult::Continue)
    }
    
    fn can_handle(&self, _event: &ModuleEvent) -> bool {
        true // Monitor all events for performance metrics
    }
    
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata {
            name: "Performance Monitor".to_string(),
            version: "1.0.0".to_string(),
            description: "System performance monitoring and metrics".to_string(),
            author: "Synco Team".to_string(),
            dependencies: vec![],
            tags: vec!["performance".to_string(), "monitoring".to_string(), "metrics".to_string()],
        }
    }
}

#[async_trait]
impl UIModule for PerformanceModule {
    fn draw(&self, f: &mut Frame, area: Rect, _context: &ModuleContext) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),  // System info
                Constraint::Length(6),  // Current metrics
                Constraint::Min(8),     // Chart
                Constraint::Length(3),  // Controls
            ])
            .split(area);

        self.draw_system_info(f, chunks[0]);
        self.draw_current_metrics(f, chunks[1]);
        self.draw_chart(f, chunks[2]);
        self.draw_controls(f, chunks[3]);
    }
    
    async fn handle_ui_event(&mut self, event: KeyEvent, _context: &mut ModuleContext) -> Result<(), ModuleError> {
        match event.code {
            crossterm::event::KeyCode::Char('m') => {
                self.cycle_metric();
            },
            crossterm::event::KeyCode::Char('t') => {
                self.cycle_time_window();
            },
            crossterm::event::KeyCode::Char('r') => {
                // Reset metrics
                self.cpu_usage.clear();
                self.memory_usage.clear();
                self.network_throughput.clear();
                self.events_processed = 0;
                self.app_start_time = Instant::now();
            },
            _ => {}
        }
        Ok(())
    }
    
    fn tab_name(&self) -> &'static str {
        "Performance"
    }
}

impl PerformanceModule {
    fn draw_system_info(&self, f: &mut Frame, area: Rect) {
        let uptime = self.get_uptime();
        let uptime_str = format!("{}h {}m {}s", 
            uptime.as_secs() / 3600,
            (uptime.as_secs() % 3600) / 60,
            uptime.as_secs() % 60);
        
        let info_lines = vec![
            Line::from(vec![
                Span::styled("Uptime: ", Style::default().fg(Color::Gray)),
                Span::styled(uptime_str, Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("Events Processed: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", self.events_processed), Style::default().fg(Color::Cyan)),
                Span::styled(format!(" ({:.2}/s)", self.events_per_second), Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::styled("Time Window: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{:.0} min", self.time_window_minutes), Style::default().fg(Color::Magenta)),
            ]),
        ];
        
        let info_widget = Paragraph::new(info_lines)
            .block(Block::default().title("System Information").borders(Borders::ALL))
            .style(Style::default().fg(Color::White));
        
        f.render_widget(info_widget, area);
    }
    
    fn draw_current_metrics(&self, f: &mut Frame, area: Rect) {
        let (cpu, memory, network) = self.get_current_metrics();
        
        let metric_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(33), Constraint::Percentage(33), Constraint::Percentage(34)])
            .split(area);
        
        // CPU Usage Gauge
        let cpu_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("CPU Usage"))
            .gauge_style(Style::default().fg(if cpu > 80.0 { Color::Red } else if cpu > 50.0 { Color::Yellow } else { Color::Green }))
            .ratio(cpu / 100.0)
            .label(format!("{:.1}%", cpu));
        f.render_widget(cpu_gauge, metric_chunks[0]);
        
        // Memory Usage
        let memory_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Memory (MB)"))
            .gauge_style(Style::default().fg(Color::Blue))
            .ratio((memory / 1000.0).min(1.0))
            .label(format!("{:.1} MB", memory));
        f.render_widget(memory_gauge, metric_chunks[1]);
        
        // Network Throughput
        let network_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Network (KB/s)"))
            .gauge_style(Style::default().fg(Color::Magenta))
            .ratio((network / 1000.0).min(1.0))
            .label(format!("{:.1} KB/s", network));
        f.render_widget(network_gauge, metric_chunks[2]);
    }
    
    fn draw_chart(&self, f: &mut Frame, area: Rect) {
        let (data, title, color) = match self.selected_metric {
            0 => (&self.cpu_usage, "CPU Usage (%)", Color::Green),
            1 => (&self.memory_usage, "Memory Usage (MB)", Color::Blue),
            2 => (&self.network_throughput, "Network Throughput (KB/s)", Color::Magenta),
            _ => (&self.cpu_usage, "CPU Usage (%)", Color::Green),
        };
        
        if data.is_empty() {
            let empty_chart = Paragraph::new("No data available yet...")
                .block(Block::default().title(title).borders(Borders::ALL))
                .style(Style::default().fg(Color::Gray));
            f.render_widget(empty_chart, area);
            return;
        }
        
        let chart_data: Vec<(f64, f64)> = data.iter().cloned().collect();
        
        let min_time = chart_data.first().map(|(t, _)| *t).unwrap_or(0.0);
        let max_time = chart_data.last().map(|(t, _)| *t).unwrap_or(1.0);
        let min_value = chart_data.iter().map(|(_, v)| *v).fold(f64::INFINITY, f64::min).min(0.0);
        let max_value = chart_data.iter().map(|(_, v)| *v).fold(f64::NEG_INFINITY, f64::max).max(100.0);
        
        let datasets = vec![
            Dataset::default()
                .name(title)
                .marker(ratatui::symbols::Marker::Braille)
                .style(Style::default().fg(color))
                .graph_type(GraphType::Line)
                .data(&chart_data)
        ];
        
        let chart = Chart::new(datasets)
            .block(Block::default().title(format!("{} [m: cycle metric | t: time window]", title)).borders(Borders::ALL))
            .x_axis(
                Axis::default()
                    .title("Time (s)")
                    .style(Style::default().fg(Color::Gray))
                    .bounds([min_time, max_time])
                    .labels(vec![
                        Span::raw(format!("{:.0}", min_time)),
                        Span::raw(format!("{:.0}", (min_time + max_time) / 2.0)),
                        Span::raw(format!("{:.0}", max_time)),
                    ])
            )
            .y_axis(
                Axis::default()
                    .title(match self.selected_metric {
                        0 => "CPU %",
                        1 => "Memory MB",
                        2 => "Net KB/s",
                        _ => "Value",
                    })
                    .style(Style::default().fg(Color::Gray))
                    .bounds([min_value, max_value])
                    .labels(vec![
                        Span::raw(format!("{:.0}", min_value)),
                        Span::raw(format!("{:.0}", (min_value + max_value) / 2.0)),
                        Span::raw(format!("{:.0}", max_value)),
                    ])
            );
        
        f.render_widget(chart, area);
    }
    
    fn draw_controls(&self, f: &mut Frame, area: Rect) {
        let controls_text = format!(
            "Controls: [m] Metric: {} | [t] Time: {:.0}min | [r] Reset",
            match self.selected_metric {
                0 => "CPU",
                1 => "Memory",
                2 => "Network",
                _ => "Unknown",
            },
            self.time_window_minutes
        );
        
        let controls = Paragraph::new(controls_text)
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL).title("Controls"));
        
        f.render_widget(controls, area);
    }
} 