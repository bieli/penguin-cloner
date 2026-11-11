//! penguin-cloner-tui
//!
//! A ratatui frontend that drives the `penguin-cloner` CLI:
//!   Picker  -> choose a process from /proc
//!   Maps    -> `penguin-cloner maps --pid N`
//!   Dump    -> `penguin-cloner dump --pid N --out DIR [flags]` (streamed live)
//!   Strings -> `penguin-cloner strings --dir DIR [--interesting-only]`
//!   Vars    -> `penguin-cloner vars --pid N --out DIR --watch S --print` (typed variable dictionary)
//!
//! Run it as root (or with CAP_SYS_PTRACE), otherwise dumps will fail:
//!   sudo PENGUIN_CLONER_BIN=./target/release/penguin-cloner ./penguin-cloner-tui

use std::{
    fs,
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};

use color_eyre::Result;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph, Row, Table, TableState},
    DefaultTerminal, Frame,
};

/// Hard cap so a huge strings dump cannot eat all RAM.
const MAX_LINES: usize = 200_000;

// ───────────────────────────── /proc scanning ─────────────────────────────

#[derive(Clone)]
struct ProcInfo {
    pid: u32,
    uid: u32,
    name: String,
    cmdline: String,
}

fn read_uid(path: &str) -> Option<u32> {
    fs::read_to_string(path)
        .ok()?
        .lines()
        .find(|l| l.starts_with("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn is_root() -> bool {
    read_uid("/proc/self/status") == Some(0)
}

fn scan_procs() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in rd.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let base = format!("/proc/{pid}");
        let name = fs::read_to_string(format!("{base}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let cmdline = fs::read(format!("{base}/cmdline"))
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .replace('\0', " ")
                    .trim()
                    .to_string()
            })
            .unwrap_or_default();
        let uid = read_uid(&format!("{base}/status")).unwrap_or(u32::MAX);
        out.push(ProcInfo {
            pid,
            uid,
            name,
            cmdline,
        });
    }
    out.sort_by_key(|p| p.pid);
    out
}

// ─────────────────────── background command runner ───────────────────────

enum Msg {
    Line(String),
    Done(bool),
}

/// Spawn `bin args...` on a worker thread and stream stdout+stderr line by line.
fn spawn_streaming(bin: String, args: Vec<String>, tx: Sender<Msg>) {
    thread::spawn(move || {
        let child = Command::new(&bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Msg::Line(format!("failed to start '{bin}': {e}")));
                let _ = tx.send(Msg::Done(false));
                return;
            }
        };
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        let tx_err = tx.clone();
        let err_thread = thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(|l| l.ok()) {
                let _ = tx_err.send(Msg::Line(line));
            }
        });
        for line in BufReader::new(stdout).lines().map_while(|l| l.ok()) {
            let _ = tx.send(Msg::Line(line));
        }
        let _ = err_thread.join();
        let ok = child.wait().map(|s| s.success()).unwrap_or(false);
        let _ = tx.send(Msg::Done(ok));
    });
}

// ──────────────────────────────── app state ───────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Screen {
    Picker,
    Maps,
    Dump,
    Strings,
    Vars,
}

struct App {
    quit: bool,
    screen: Screen,
    bin: String,
    root: bool,
    status: String,

    // picker
    procs: Vec<ProcInfo>,
    filter: String,
    filtering: bool,
    table_state: TableState,
    selected: Option<ProcInfo>,

    // dump options
    heap_stack_only: bool,
    include_file_backed: bool,
    no_freeze: bool,
    combined: bool,
    out_dir: String,
    editing_out: bool,
    interesting_only: bool,
    dump_vars: bool,
    watch_secs: u32,

    // command output pane
    output: Vec<String>,
    scroll: usize,
    follow: bool,
    running: bool,
    rx: Option<Receiver<Msg>>,
}

impl App {
    fn new() -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self {
            quit: false,
            screen: Screen::Picker,
            bin: std::env::var("PENGUIN_CLONER_BIN").unwrap_or_else(|_| "penguin-cloner".into()),
            root: is_root(),
            status: String::new(),
            procs: scan_procs(),
            filter: String::new(),
            filtering: false,
            table_state,
            selected: None,
            heap_stack_only: false,
            include_file_backed: false,
            no_freeze: false,
            combined: false,
            out_dir: String::new(),
            editing_out: false,
            interesting_only: true,
            dump_vars: true,
            watch_secs: 2,
            output: Vec::new(),
            scroll: 0,
            follow: false,
            running: false,
            rx: None,
        }
    }

    // ── main loop ──

    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while !self.quit {
            self.pump();
            terminal.draw(|f| self.draw(f))?;
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press {
                        self.on_key(k.code, k.modifiers);
                    }
                }
            }
        }
        Ok(())
    }

    /// Drain messages coming from the worker thread.
    fn pump(&mut self) {
        let Some(rx) = &self.rx else { return };
        let mut done = None;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                Msg::Line(l) => {
                    if self.output.len() < MAX_LINES {
                        self.output.push(l);
                    }
                }
                Msg::Done(ok) => done = Some(ok),
            }
        }
        if let Some(ok) = done {
            self.running = false;
            self.rx = None;
            self.status = if ok {
                "finished OK".into()
            } else {
                "finished with errors (see output)".into()
            };
        }
    }

    // ── command helpers ──

    fn run_cmd(&mut self, args: Vec<String>, follow: bool) {
        self.output.clear();
        self.scroll = 0;
        self.follow = follow;
        self.running = true;
        self.status = "running…".into();
        self.output
            .push(format!("$ {} {}", self.bin, args.join(" ")));
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        spawn_streaming(self.bin.clone(), args, tx);
    }

    fn stop_output(&mut self) {
        self.output.clear();
        self.scroll = 0;
        self.running = false;
        self.rx = None;
        self.status.clear();
    }

    fn load_maps(&mut self) {
        if let Some(p) = &self.selected {
            let args = vec!["maps".into(), "--pid".into(), p.pid.to_string()];
            self.run_cmd(args, false);
        }
    }

    fn start_dump(&mut self) {
        let Some(p) = &self.selected else { return };
        let mut args: Vec<String> = vec![
            "dump".into(),
            "--pid".into(),
            p.pid.to_string(),
            "--out".into(),
            self.out_dir.clone(),
        ];
        if self.heap_stack_only {
            args.push("--heap-stack-only".into());
        }
        if self.include_file_backed {
            args.push("--include-file-backed".into());
        }
        if self.no_freeze {
            args.push("--no-freeze".into());
        }
        if self.combined {
            args.push("--combined".into());
        }
        if self.dump_vars {
            args.push("--vars".into());
        }
        self.run_cmd(args, true);
    }

    /// Typed variable dictionary of the live process (no memory dump), watched for a few seconds.
    fn load_vars(&mut self) {
        let Some(p) = &self.selected else { return };
        let mut args: Vec<String> = vec![
            "vars".into(),
            "--pid".into(),
            p.pid.to_string(),
            "--out".into(),
            self.out_dir.clone(),
            "--print".into(),
        ];
        if self.watch_secs > 0 {
            args.push("--watch".into());
            args.push(self.watch_secs.to_string());
        }
        self.run_cmd(args, false);
    }

    fn load_strings(&mut self) {
        let mut args: Vec<String> = vec!["strings".into(), "--dir".into(), self.out_dir.clone()];
        if self.interesting_only {
            args.push("--interesting-only".into());
        }
        self.run_cmd(args, false);
    }

    // ── picker helpers ──

    fn visible(&self) -> Vec<&ProcInfo> {
        let q = self.filter.to_lowercase();
        self.procs
            .iter()
            .filter(|p| {
                q.is_empty()
                    || p.name.to_lowercase().contains(&q)
                    || p.cmdline.to_lowercase().contains(&q)
                    || p.pid.to_string().contains(&q)
            })
            .collect()
    }

    fn reset_sel(&mut self) {
        let n = self.visible().len();
        self.table_state.select(if n > 0 { Some(0) } else { None });
    }

    fn move_sel(&mut self, delta: isize) {
        let n = self.visible().len();
        if n == 0 {
            self.table_state.select(None);
            return;
        }
        let cur = self.table_state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, n as isize - 1) as usize;
        self.table_state.select(Some(next));
    }

    fn open_selected(&mut self) {
        let target = self
            .table_state
            .selected()
            .and_then(|i| self.visible().get(i).map(|p| (**p).clone()));
        let Some(p) = target else { return };
        self.out_dir = format!("./clone-{}", p.pid);
        self.selected = Some(p);
        self.screen = Screen::Maps;
        self.load_maps();
    }

    // ── input ──

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        if mods.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        match self.screen {
            Screen::Picker => self.key_picker(code),
            Screen::Maps => self.key_maps(code),
            Screen::Dump => self.key_dump(code),
            Screen::Strings => self.key_strings(code),
            Screen::Vars => self.key_vars(code),
        }
    }

    fn scroll_keys(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.follow = false;
                self.scroll = self.scroll.saturating_add(1);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.follow = false;
                self.scroll = self.scroll.saturating_sub(1);
            }
            KeyCode::PageDown => {
                self.follow = false;
                self.scroll = self.scroll.saturating_add(20);
            }
            KeyCode::PageUp => {
                self.follow = false;
                self.scroll = self.scroll.saturating_sub(20);
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.follow = false;
                self.scroll = 0;
            }
            KeyCode::Char('G') | KeyCode::End => self.follow = true,
            _ => return false,
        }
        true
    }

    fn key_picker(&mut self, code: KeyCode) {
        if self.filtering {
            match code {
                KeyCode::Esc | KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.reset_sel();
                }
                KeyCode::Char(c) => {
                    self.filter.push(c);
                    self.reset_sel();
                }
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Esc => {
                if self.filter.is_empty() {
                    self.quit = true;
                } else {
                    self.filter.clear();
                    self.reset_sel();
                }
            }
            KeyCode::Char('/') => self.filtering = true,
            KeyCode::Char('r') => {
                self.procs = scan_procs();
                self.reset_sel();
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::PageDown => self.move_sel(15),
            KeyCode::PageUp => self.move_sel(-15),
            KeyCode::Enter => self.open_selected(),
            _ => {}
        }
    }

    fn key_maps(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.stop_output();
                self.screen = Screen::Picker;
            }
            KeyCode::Char('d') => {
                self.stop_output();
                self.screen = Screen::Dump;
            }
            other => {
                self.scroll_keys(other);
            }
        }
    }

    fn key_dump(&mut self, code: KeyCode) {
        if self.editing_out {
            match code {
                KeyCode::Esc | KeyCode::Enter => self.editing_out = false,
                KeyCode::Backspace => {
                    self.out_dir.pop();
                }
                KeyCode::Char(c) => self.out_dir.push(c),
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Esc | KeyCode::Char('q') if !self.running => {
                self.screen = Screen::Maps;
                self.load_maps();
            }
            KeyCode::Char('h') if !self.running => self.heap_stack_only = !self.heap_stack_only,
            KeyCode::Char('f') if !self.running => {
                self.include_file_backed = !self.include_file_backed
            }
            KeyCode::Char('n') if !self.running => self.no_freeze = !self.no_freeze,
            KeyCode::Char('c') if !self.running => self.combined = !self.combined,
            KeyCode::Char('v') if !self.running => self.dump_vars = !self.dump_vars,
            KeyCode::Char('w') if !self.running => {
                self.screen = Screen::Vars;
                self.load_vars();
            }
            KeyCode::Char('o') if !self.running => self.editing_out = true,
            KeyCode::Enter if !self.running => self.start_dump(),
            KeyCode::Char('s') if !self.running => {
                self.screen = Screen::Strings;
                self.load_strings();
            }
            other => {
                self.scroll_keys(other);
            }
        }
    }

    fn key_vars(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.stop_output();
                self.screen = Screen::Dump;
            }
            // 0 = no watching (symbols + code references only), otherwise observe N seconds
            KeyCode::Char('t') if !self.running => {
                self.watch_secs = match self.watch_secs {
                    0 => 2,
                    2 => 5,
                    _ => 0,
                };
                self.load_vars();
            }
            KeyCode::Char('r') if !self.running => self.load_vars(),
            other => {
                self.scroll_keys(other);
            }
        }
    }

    fn key_strings(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.stop_output();
                self.screen = Screen::Dump;
            }
            KeyCode::Char('i') if !self.running => {
                self.interesting_only = !self.interesting_only;
                self.load_strings();
            }
            other => {
                self.scroll_keys(other);
            }
        }
    }

    // ── drawing ──

    fn draw(&mut self, f: &mut Frame) {
        let [head, body, foot] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .areas(f.area());

        self.draw_header(f, head);
        match self.screen {
            Screen::Picker => self.draw_picker(f, body),
            Screen::Maps => {
                let title = match &self.selected {
                    Some(p) => format!(" Memory maps — PID {} ({}) ", p.pid, p.name),
                    None => " Memory maps ".into(),
                };
                self.draw_output(f, body, &title);
            }
            Screen::Dump => self.draw_dump(f, body),
            Screen::Strings => {
                let title = format!(
                    " Strings — {} (interesting only: {}) ",
                    self.out_dir,
                    if self.interesting_only { "on" } else { "off" }
                );
                self.draw_output(f, body, &title);
            }
            Screen::Vars => {
                let title = format!(
                    " Variables — {} (watch: {}s) ",
                    self.out_dir, self.watch_secs
                );
                self.draw_output(f, body, &title);
            }
        }
        self.draw_footer(f, foot);
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let root = if self.root {
            Span::styled("root", Style::new().fg(Color::Green))
        } else {
            Span::styled(
                "not root — dumps will likely fail (use sudo)",
                Style::new().fg(Color::Red),
            )
        };
        let line = Line::from(vec![
            Span::styled(
                " 🐧 penguin-cloner ",
                Style::new()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            root,
        ]);
        f.render_widget(Paragraph::new(line), area);
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let help = match self.screen {
            Screen::Picker => "↑↓/jk move  / filter  r refresh  Enter open  q quit",
            Screen::Maps => "↑↓/jk scroll  d dump options  Esc back",
            Screen::Dump if self.editing_out => "type output dir  Enter/Esc done",
            Screen::Dump if self.running => "dumping… ↑↓ scroll  G follow",
            Screen::Dump => {
                "h f n c v toggles  o out dir  Enter START  s strings  w variables  Esc back"
            }
            Screen::Vars => "↑↓/jk scroll  t watch time (0/2/5s)  r rerun  Esc back",
            Screen::Strings => "↑↓/jk scroll  i toggle interesting  Esc back",
        };
        let line = Line::from(vec![
            Span::styled(help, Style::new().fg(Color::DarkGray)),
            Span::raw("   "),
            Span::styled(self.status.as_str(), Style::new().fg(Color::Yellow)),
        ]);
        f.render_widget(Paragraph::new(line), area);
    }

    fn draw_picker(&mut self, f: &mut Frame, area: Rect) {
        let [bar, list] = Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).areas(area);

        let cursor = if self.filtering { "▏" } else { "" };
        f.render_widget(
            Paragraph::new(format!("{}{}", self.filter, cursor))
                .block(Block::bordered().title(" Filter ( / ) ")),
            bar,
        );

        let rows: Vec<Row> = self
            .visible()
            .iter()
            .map(|p| {
                let uid = if p.uid == u32::MAX {
                    "?".to_string()
                } else {
                    p.uid.to_string()
                };
                let cmd = if p.cmdline.is_empty() {
                    format!("[{}]", p.name)
                } else {
                    p.cmdline.clone()
                };
                Row::new(vec![p.pid.to_string(), uid, p.name.clone(), cmd])
            })
            .collect();
        let title = format!(" Processes ({}) ", rows.len());

        let table = Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Length(7),
                Constraint::Length(18),
                Constraint::Min(10),
            ],
        )
        .header(
            Row::new(["PID", "UID", "NAME", "CMDLINE"])
                .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        )
        .block(Block::bordered().title(title))
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");

        f.render_stateful_widget(table, list, &mut self.table_state);
    }

    fn draw_dump(&mut self, f: &mut Frame, area: Rect) {
        let [opts, out] =
            Layout::vertical([Constraint::Length(10), Constraint::Min(3)]).areas(area);

        let title = match &self.selected {
            Some(p) => format!(" Dump options — PID {} ({}) ", p.pid, p.name),
            None => " Dump options ".into(),
        };

        let flag = |on: bool, key: char, label: &str| -> Line<'static> {
            Line::from(vec![
                Span::raw(if on { "[x] " } else { "[ ] " }),
                Span::styled(format!("({key}) "), Style::new().fg(Color::Yellow)),
                Span::raw(label.to_string()),
            ])
        };
        let cursor = if self.editing_out { "▏" } else { "" };
        let lines = vec![
            flag(
                self.heap_stack_only,
                'h',
                "heap + stack only (smaller dump)",
            ),
            flag(
                self.include_file_backed,
                'f',
                "include file-backed maps (large)",
            ),
            flag(
                self.no_freeze,
                'n',
                "do not freeze process (racy, no ptrace attach)",
            ),
            flag(self.combined, 'c', "write memory_combined.bin"),
            flag(
                self.dump_vars,
                'v',
                "also write variables.json (typed int/float/string dictionary)",
            ),
            Line::from(vec![
                Span::styled("(o) ", Style::new().fg(Color::Yellow)),
                Span::raw(format!("output dir: {}{}", self.out_dir, cursor)),
            ]),
            Line::raw(""),
            Line::styled(
                "The target is briefly frozen via ptrace unless (n) is on.",
                Style::new().fg(Color::DarkGray),
            ),
        ];
        f.render_widget(
            Paragraph::new(lines).block(Block::bordered().title(title)),
            opts,
        );

        let out_title = if self.running {
            " Output (running…) "
        } else {
            " Output "
        };
        self.draw_output(f, out, out_title);
    }

    /// Scrollable output pane that only renders the visible window of lines,
    /// so 100k+ lines of strings stay fast.
    fn draw_output(&mut self, f: &mut Frame, area: Rect, title: &str) {
        let block = Block::bordered().title(title.to_string());
        let inner = block.inner(area);
        f.render_widget(block, area);

        let h = inner.height as usize;
        let max_scroll = self.output.len().saturating_sub(h);
        if self.follow {
            self.scroll = max_scroll;
        } else {
            self.scroll = self.scroll.min(max_scroll);
        }

        let in_maps = self.screen == Screen::Maps;
        let lines: Vec<Line> = self
            .output
            .iter()
            .skip(self.scroll)
            .take(h)
            .map(|l| style_line(l, in_maps))
            .collect();
        f.render_widget(Paragraph::new(lines), inner);
    }
}

/// Colour helper: highlight the command echo, and in the maps view flag
/// writable+executable regions (red) and executable ones (green).
fn style_line(l: &str, in_maps: bool) -> Line<'_> {
    if l.starts_with("$ ") {
        return Line::styled(l, Style::new().fg(Color::Cyan));
    }
    if in_maps {
        if let Some(perms) = l.split_whitespace().nth(1) {
            if perms.len() >= 3 {
                let w = perms.as_bytes()[1] == b'w';
                let x = perms.as_bytes()[2] == b'x';
                if w && x {
                    return Line::styled(l, Style::new().fg(Color::Red));
                } else if x {
                    return Line::styled(l, Style::new().fg(Color::Green));
                }
            }
        }
    }
    Line::raw(l)
}

fn main() -> Result<()> {
    color_eyre::install()?;
    // ratatui::init() enters raw mode + alt screen and installs a panic hook
    // that restores the terminal, so a crash never leaves your shell broken.
    let mut terminal = ratatui::init();
    let result = App::new().run(&mut terminal);
    ratatui::restore();
    result
}
