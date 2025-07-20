use std::time::Duration;
use tokio::time::sleep;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Terminal, Frame,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io;
use crate::consts::DeviceId;
use super::{network, files, logs};

pub struct SyncoUI {
    pub should_quit: bool,
    pub selected_tab: usize,
}

impl SyncoUI {
    pub fn new() -> Self {
        Self {
            should_quit: false,
            selected_tab: 0,
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Main loop
        loop {
            terminal.draw(|f| self.draw(f))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.should_quit = true;
                        }
                        KeyCode::Tab => {
                            self.selected_tab = (self.selected_tab + 1) % 3;
                        }
                        KeyCode::Char('1') => self.selected_tab = 0,
                        KeyCode::Char('2') => self.selected_tab = 1,
                        KeyCode::Char('3') => self.selected_tab = 2,
                        _ => {}
                    }
                }
            }

            if self.should_quit {
                break;
            }

            sleep(Duration::from_millis(50)).await;
        }

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

    fn draw(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Min(0),     // Main content
                Constraint::Length(3),  // Footer
            ])
            .split(f.area());

        self.draw_header(f, chunks[0]);
        self.draw_main_content(f, chunks[1]);
        self.draw_footer(f, chunks[2]);
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let header = Paragraph::new(format!("Synco - P2P File Sync | Device ID: {}", &DeviceId[..8]))
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(header, area);
    }

    fn draw_main_content(&self, f: &mut Frame, area: Rect) {
        let tabs = ["[1] Network", "[2] Files", "[3] Logs"];
        let tab_titles: Vec<Line> = tabs.iter().enumerate().map(|(i, &tab)| {
            if i == self.selected_tab {
                Line::from(Span::styled(tab, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
            } else {
                Line::from(Span::styled(tab, Style::default().fg(Color::White)))
            }
        }).collect();

        let tab_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(area);

        let tab_bar = Paragraph::new(tab_titles)
            .style(Style::default().fg(Color::White));
        f.render_widget(tab_bar, tab_chunks[0]);

        match self.selected_tab {
            0 => network::draw(f, tab_chunks[1]),
            1 => files::draw(f, tab_chunks[1]),
            2 => logs::draw(f, tab_chunks[1]),
            _ => {}
        }
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let footer = Paragraph::new("Press 'q' to quit | Tab/1-3 to switch tabs")
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, area);
    }
}

pub async fn start_ui() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ui = SyncoUI::new();
    ui.run().await
} 