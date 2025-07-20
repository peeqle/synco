use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn draw(f: &mut Frame, area: Rect) {
    let logs = vec![
        Line::from("System Logs:"),
        Line::from("Application started"),
    ];

    let logs_widget = Paragraph::new(logs)
        .block(Block::default().title("System Logs").borders(Borders::ALL))
        .style(Style::default().fg(Color::White))
        .scroll((0, 0));

    f.render_widget(logs_widget, area);
} 