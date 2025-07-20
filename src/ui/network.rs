use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use std::sync::Arc;
use crate::device_manager::DefaultDeviceManager;
use crate::consts::{DEFAULT_SERVER_PORT, DEFAULT_LISTENING_PORT};

pub fn draw(f: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    draw_device_list(f, chunks[0]);
    draw_network_status(f, chunks[1]);
}

fn draw_device_list(f: &mut Frame, area: Rect) {
    // TODO: Replace with actual device data from DefaultDeviceManager
    let devices: Vec<ListItem> = Vec::new();
    
    let device_list = List::new(devices)
        .block(Block::default().title("Known Devices").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    f.render_widget(device_list, area);
}

fn draw_network_status(f: &mut Frame, area: Rect) {
    let network_info = vec![
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::White)),
            Span::styled("Initializing", Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled("Mode: ", Style::default().fg(Color::White)),
            Span::styled("Bootstrap", Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("UDP Port: ", Style::default().fg(Color::White)),
            Span::styled(DEFAULT_LISTENING_PORT.to_string(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("TCP Port: ", Style::default().fg(Color::White)),
            Span::styled(DEFAULT_SERVER_PORT.to_string(), Style::default().fg(Color::Cyan)),
        ]),
    ];

    let network_status = Paragraph::new(network_info)
        .block(Block::default().title("Network Status").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    f.render_widget(network_status, area);
} 