use anyhow::Result;
use once_cell::sync::Lazy;

use probing_common::Process;
use ratatui::crossterm::event::KeyCode;
use ratatui::prelude::*;
use ratatui::widgets::Scrollbar;
use tui_tree_widget::{Tree, TreeItem, TreeState};

use super::app_style;
use super::read_info::read_process_info;

#[derive(Default, Debug)]
pub struct ProcessTab {
    state: TreeState<String>,
    items: Vec<TreeItem<'static, String>>,
}

pub static mut PROCESS_TAB: Lazy<ProcessTab> = Lazy::new(|| ProcessTab::default());

pub fn handle_key_event(code: KeyCode) -> Result<()> {
    unsafe {
        match code {
            KeyCode::Char('\n') | KeyCode::Enter => PROCESS_TAB.state.toggle_selected(),
            KeyCode::Up => PROCESS_TAB.state.key_up(),
            KeyCode::Down => PROCESS_TAB.state.key_down(),
            KeyCode::Left => PROCESS_TAB.state.key_left(),
            KeyCode::Right => PROCESS_TAB.state.key_right(),
            _ => false,
        };
    }
    Ok(())
}

fn format_json_key(key: &str, val: String) -> TreeItem<'static, String> {
    use nu_ansi_term::Color::Blue;
    use nu_ansi_term::Color::DarkGray;
    TreeItem::new_leaf(
        key.to_string(),
        format!(
            "{} {}{}",
            Blue.paint(key),
            DarkGray.dimmed().paint(":"),
            DarkGray.dimmed().paint(val)
        ),
    )
}

fn format_json_key_longstr(
    key: &str,
    val: String,
    sep1: &str,
    sep2: &str,
) -> TreeItem<'static, String> {
    let children: Vec<_> = val
        .split_terminator(sep1)
        .filter_map(|kv| {
            if let Some((name, value)) = kv.split_once(sep2) {
                Some(format_json_key(name, value.to_string()))
            } else {
                None
            }
        })
        .collect();
    use nu_ansi_term::Color::Blue;
    use nu_ansi_term::Color::DarkGray;
    TreeItem::new(
        key.to_string(),
        format!(
            "{} {}{}",
            Blue.bold().paint(key),
            DarkGray.dimmed().paint(":"),
            DarkGray
                .dimmed()
                .paint(format!("{} children", children.len()))
        ),
        children,
    )
    .unwrap()
}

fn format_json_key_array(key: &str, val: Vec<String>) -> TreeItem<'static, String> {
    use nu_ansi_term::Color::Blue;
    use nu_ansi_term::Color::DarkGray;
    let children: Vec<_> = val
        .iter()
        .enumerate()
        .map(|(i, v)| {
            TreeItem::new_leaf(
                format!("{i}"),
                format!(
                    "{}{}",
                    DarkGray.dimmed().paint(format!("[{}]=", i)),
                    Blue.bold().paint(v),
                ),
            )
        })
        .collect();
    TreeItem::new(
        key.to_string(),
        format!(
            "{} {}{}",
            Blue.bold().paint(key),
            DarkGray.dimmed().paint(":"),
            DarkGray
                .dimmed()
                .paint(format!("{} children", children.len()))
        ),
        children,
    )
    .unwrap()
}

impl ProcessTab {
    pub fn draw(&mut self, area: Rect, buf: &mut Buffer)
    where
        Self: Sized,
    {
        if self.items.is_empty() {
            let info = read_process_info();
            let info = serde_json::from_str::<Process>(&info).unwrap_or_default();
            self.items = vec![
                format_json_key("pid", format!("{}", info.pid)),
                format_json_key("exe", info.exe),
                format_json_key("cmd", info.cmd),
                format_json_key("cwd", info.cwd),
                format_json_key_longstr("env", info.env, "\n", "="),
                format_json_key("main_thread", format!("{}", info.main_thread)),
                format_json_key_array(
                    "threads",
                    info.threads.iter().map(|t| format!("{}", t)).collect(),
                ),
            ];
        }
        let tree = Tree::new(&self.items)
            .expect("all item identifiers are unique")
            .block(app_style::border_header(Some(
                "Process Info (`Enter` to select)",
            )))
            .experimental_scrollbar(
                Scrollbar::new(ratatui::widgets::ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .track_symbol(None)
                    .end_symbol(None)
                    .into(),
            )
            .node_closed_symbol(" +")
            .node_open_symbol(" -")
            .highlight_symbol(">");
        ratatui::prelude::StatefulWidget::render(tree, area, buf, &mut self.state);
    }
}
