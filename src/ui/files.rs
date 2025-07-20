use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

pub fn draw(f: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    draw_file_list(f, chunks[0]);
    draw_file_operations(f, chunks[1]);
}

fn draw_file_list(f: &mut Frame, area: Rect) {
    // TODO: Replace with actual file data
    let files: Vec<ListItem> = Vec::new();

    let file_list = List::new(files)
        .block(Block::default().title("Synchronized Files").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    f.render_widget(file_list, area);
}

fn draw_file_operations(f: &mut Frame, area: Rect) {
    let operations = vec![
        Line::from("Recent Operations:"),
        Line::from("No operations yet"),
    ];

    let operations_widget = Paragraph::new(operations)
        .block(Block::default().title("File Operations").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    f.render_widget(operations_widget, area);
} 