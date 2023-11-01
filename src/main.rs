use ansi_term::Style;
use anyhow::Result;
use labeler::{
    config::Config, matcher::TitleMatch, CliConf, ClusterId, ConfigType, FilterOp, FilterType,
    Qualifier,
};
use log::{error, info};
use rustyline::{config::Configurer, error::ReadlineError};
use rustyline_derive::{Helper, Highlighter, Hinter, Validator};
use std::{collections::LinkedList, str::FromStr};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    config_path: String,
}

fn main() {
    env_logger::init();
    let opt = Opt::from_args();
    let cfg = Config::init(&opt.config_path);

    if let Err(e) = run(&cfg) {
        error!("{:#}", e);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliCmd {
    ClusterID,
    Event(FilterType, FilterOp),
    Exit,
    Filter(FilterType, FilterOp),
    GoNext,
    GoPrev,
    Help,
    Jump,
    QuitProgram,
    Save(bool),
    Set(ConfigType),
    SetQualifier(bool),
    Status,
    Undefined,
}

#[derive(Helper, Hinter, Highlighter, Validator)]
struct CmdCompleter {
    commands: Vec<&'static str>,
}
const CMDLIST: &[&str] = &[
    "/event regex",
    "/event clear",
    "/filter count",
    "/filter label",
    "/filter qualifier benign",
    "/filter qualifier mixed",
    "/filter qualifier suspicious",
    "/filter qualifier unknown",
    "/filter regex",
    "/filter score",
    "/help",
    "/quit",
    "/save",
    "/save force",
    "/set benign",
    "/set benign all",
    "/set csvstyle off",
    "/set csvstyle on",
    "/set mixed",
    "/set mixed all",
    "/set reverse off",
    "/set reverse on",
    "/set samples off",
    "/set samples on",
    "/set signature off",
    "/set signature on",
    "/set suspicious",
    "/set suspicious all",
    "/set tokens off",
    "/set tokens on",
    "/set unknown",
    "/set unknown all",
    "/status",
    "/x",
];

impl rustyline::completion::Completer for CmdCompleter {
    type Candidate = String;
    fn complete(
        &self,
        line: &str,
        _pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<String>)> {
        let out = self
            .commands
            .iter()
            .filter_map(|cmd| {
                if cmd.starts_with(line) {
                    Some((*cmd).to_string())
                } else {
                    None
                }
            })
            .collect();
        Ok((0, out))
    }
}

const COMMAND_HISTORY_FILE: &str = ".cli_history.txt";

/// # Errors
///
/// Will return `Err` if database connection failed or labeldb_* tables are not exist in database.
#[allow(clippy::too_many_lines)]
fn run(cfg: &Config) -> Result<()> {
    let mut champion = TitleMatch::new(cfg)?;
    let mut limit = champion.count_clusters();
    champion.show_statistics();

    let mut rl = rustyline::Editor::<CmdCompleter>::new();
    let completer = CmdCompleter {
        commands: CMDLIST.to_vec(),
    };
    rl.set_helper(Some(completer));
    rl.set_completion_type(rustyline::CompletionType::List);
    let _r = rl.load_history(COMMAND_HISTORY_FILE);

    let mut prompt: LinkedList<(String, Option<usize>, usize)> = LinkedList::new();
    let style = Style::new().reverse();
    let mut title: String = String::from("Clusters");
    let mut tag: String;
    let mut ticks: Option<usize> = None;
    let mut clicfg = CliConf::default();

    loop {
        tag = if ticks.is_none() {
            format!("\n{} [{}]# ", style.paint(&title), limit)
        } else {
            format!(
                "\n{} [{}/{}]# ",
                style.paint(&title),
                ticks.unwrap_or(0) + 1,
                limit
            )
        };
        let (cmdtype, opt) = get_user_input(&mut rl, &tag);
        info!("Command: {:?}, option: {:?}", cmdtype, opt);
        match cmdtype {
            CliCmd::ClusterID => {
                if let Some(s) = opt {
                    if let Ok(cid) = s.parse::<ClusterId>() {
                        ticks = champion.find_cluster(cid);
                    }
                }
            }
            CliCmd::Event(t, _) => {
                do_event_filtering(&mut champion, t, opt.as_deref(), &ticks);
            }
            CliCmd::Exit => {
                if !prompt.is_empty() {
                    if champion.remove_filter().is_ok() {
                        let t = prompt.pop_back().unwrap();
                        title = t.0;
                        ticks = t.1;
                        limit = t.2;
                    } else {
                        println!("Error: failed to exit layers.");
                    }
                }
                continue;
            }
            CliCmd::Filter(t, op) => {
                if let Some(len) = do_filtering(&mut champion, t, op, opt.as_deref()) {
                    prompt.push_back((title.to_string(), ticks, limit));
                    if let Some(s) = opt {
                        title = format!("{}({:?} {} {})", title, t, op, s);
                    } else if t == FilterType::Label {
                        title = format!("{}({:?} {} All)", title, t, op);
                    }
                    limit = len;
                    ticks = None;
                }
                continue;
            }
            CliCmd::GoNext | CliCmd::GoPrev => {
                ticks = Some(do_goto(cmdtype, ticks, clicfg.is_reverse_on()));
            }
            CliCmd::Help => {
                show_help();
                continue;
            }
            CliCmd::Jump => {
                if let Some(s) = opt {
                    if let Ok(i) = s.parse::<usize>() {
                        if i > 0 {
                            ticks = Some(i - 1);
                        }
                    }
                }
            }
            CliCmd::QuitProgram => break,
            // CliCmd::Save(_) => {
            //     /* save qualifiers and labels */
            //     // let _ = champion.cli_save(cfg);
            //     continue;
            // }
            CliCmd::Set(x) => {
                clicfg.set(x);
                println!("set {:?}\n", x);
                continue;
            }
            CliCmd::SetQualifier(x) => {
                if let Some(s) = opt {
                    if let Some(v) = ticks {
                        champion.set_qualifier(v, &s, x);
                    }
                }
            }
            CliCmd::Save(_) | CliCmd::Status => {
                // champion.print_statistics();
                continue;
            }
            CliCmd::Undefined => {
                println!("Undefined command!\n");
                continue;
            }
        }

        if let Some(v) = ticks {
            if v >= limit {
                ticks = Some(limit - 1);
            }
        } else {
            ticks = Some(0);
        }

        if let Some(v) = ticks {
            champion.print_cluster(v, &clicfg);
        }
    }

    rl.save_history(COMMAND_HISTORY_FILE)?;
    Ok(())
}

fn do_goto(cmd: CliCmd, ticks: Option<usize>, reverse: bool) -> usize {
    if let Some(v) = ticks {
        if (cmd == CliCmd::GoNext && !reverse) || (cmd == CliCmd::GoPrev && reverse) {
            v + 1
        } else if v == 0 {
            0
        } else {
            v - 1
        }
    } else {
        0
    }
}

fn do_event_filtering(
    champion: &mut TitleMatch,
    ft: FilterType,
    pattern: Option<&str>,
    ticks: &Option<usize>,
) {
    match ft {
        FilterType::NoFilter | FilterType::Regex => {
            let _r = champion.filter_event(ft, pattern, ticks);
        }
        _ => {}
    }
}

fn do_filtering(
    champion: &mut TitleMatch,
    ft: FilterType,
    op: FilterOp,
    pattern: Option<&str>,
) -> Option<usize> {
    let len = match ft {
        FilterType::Count | FilterType::Qualifier | FilterType::Score => {
            if let Some(s) = pattern {
                champion.filter_by(ft, op, s)
            } else {
                None
            }
        }
        FilterType::Label => {
            if let Some(s) = pattern {
                champion.filter_by_label(ft, op, Some(s))
            } else {
                champion.filter_by_label(ft, op, None)
            }
        }
        FilterType::Regex => {
            if let Some(s) = pattern {
                champion.filter_by_regex(s)
            } else {
                None
            }
        }
        _ => None,
    };

    if let Some(l) = len {
        println!("Matched clusters = {}\n", l);
    } else {
        println!("No matched clusters.\n");
    }

    len
}

#[allow(clippy::too_many_lines)]
fn get_user_input(rl: &mut rustyline::Editor<CmdCompleter>, tag: &str) -> (CliCmd, Option<String>) {
    let input = rl.readline(tag);
    let line = match input {
        Ok(l) => {
            rl.add_history_entry(l.as_str());
            l
        }
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
            return (CliCmd::QuitProgram, None);
        }
        Err(_) => return (CliCmd::Undefined, None),
    };

    let line = line.trim();
    if line.trim().is_empty() {
        return (CliCmd::GoNext, None);
    }

    if line.len() == 1 {
        match line {
            "b" | "p" => return (CliCmd::GoPrev, None),
            "h" | "?" => return (CliCmd::Help, None),
            _ => {}
        }
    }

    if line.parse::<usize>().is_ok() {
        return (CliCmd::Jump, Some(line.to_string()));
    } else if line.starts_with('#') {
        if let Some(s) = line.get(1..) {
            if s.parse::<usize>().is_ok() {
                return (CliCmd::ClusterID, Some((*s).to_string()));
            }
        }
    }

    let mut ls: Vec<&str> = line.split_whitespace().collect();
    let pattern: String;
    if ls.len() > 4 {
        pattern = ls[3..].join(" ");
        ls.resize(3, " ");
        ls.push(&pattern);
    }
    match &ls[..] {
        ["/event", "clear"] => return (CliCmd::Event(FilterType::NoFilter, FilterOp::EQ), None),
        ["/event", "regex", x] => {
            return (
                CliCmd::Event(FilterType::Regex, FilterOp::EQ),
                Some((*x).to_string()),
            )
        }
        ["/filter", "count", x, y] => {
            if let Ok(op) = FilterOp::from_str(*x) {
                if y.parse::<usize>().is_ok() {
                    return (
                        CliCmd::Filter(FilterType::Count, op),
                        Some((*y).to_string()),
                    );
                }
            }
        }
        ["/filter", "label"] => return (CliCmd::Filter(FilterType::Label, FilterOp::EQ), None),
        ["/filter", "label", x] => {
            return (
                CliCmd::Filter(FilterType::Label, FilterOp::EQ),
                Some((*x).to_string()),
            )
        }
        ["/filter", "qualifier", x] => {
            if Qualifier::from_str(x).is_ok() {
                return (
                    CliCmd::Filter(FilterType::Qualifier, FilterOp::EQ),
                    Some((*x).to_string()),
                );
            }
        }
        ["/filter", "regex", x] => {
            return (
                CliCmd::Filter(FilterType::Regex, FilterOp::EQ),
                Some((*x).to_string()),
            )
        }
        ["/filter", "score", x, y] => {
            if let Ok(op) = FilterOp::from_str(*x) {
                if y.parse::<f64>().is_ok() {
                    return (
                        CliCmd::Filter(FilterType::Score, op),
                        Some((*y).to_string()),
                    );
                }
            }
        }
        ["/h" | "/help" | "/?"] => return (CliCmd::Help, None),
        ["/q" | "/quit"] => return (CliCmd::QuitProgram, None),
        ["/save"] => return (CliCmd::Save(false), None),
        ["/save", "force"] => return (CliCmd::Save(true), None),
        ["/set", x] => match *x {
            "benign" => return (CliCmd::SetQualifier(false), Some(String::from("benign"))),
            "mixed" => return (CliCmd::SetQualifier(false), Some(String::from("mixed"))),
            "suspicious" => {
                return (
                    CliCmd::SetQualifier(false),
                    Some(String::from("suspicious")),
                )
            }
            "unknown" => return (CliCmd::SetQualifier(false), Some(String::from("unknown"))),
            _ => {}
        },
        ["/set", x, y] => {
            let mut all: bool = false;
            let mut op: bool = false;
            let mut count: usize = 0;
            match *y {
                "on" => op = true,
                "off" => op = false,
                "all" => all = true,
                _ => {
                    if let Ok(c) = (*y).parse::<usize>() {
                        count = c;
                    } else {
                        return (CliCmd::Undefined, None);
                    }
                }
            };
            match *x {
                "benign" => return (CliCmd::SetQualifier(all), Some(String::from("benign"))),
                "mixed" => return (CliCmd::SetQualifier(all), Some(String::from("mixed"))),
                "reverse" => return (CliCmd::Set(ConfigType::Reverse(op)), None),
                "samples" => return (CliCmd::Set(ConfigType::Samples(op)), None),
                "samplescount" => return (CliCmd::Set(ConfigType::SamplesCount(count)), None),
                "signature" => return (CliCmd::Set(ConfigType::Signature(op)), None),
                "suspicious" => {
                    return (CliCmd::SetQualifier(all), Some(String::from("suspicious")))
                }
                "tokens" => return (CliCmd::Set(ConfigType::Tokens(op)), None),
                "unknown" => return (CliCmd::SetQualifier(all), Some(String::from("unknown"))),
                _ => {}
            }
        }
        ["/status"] => return (CliCmd::Status, None),
        ["/x"] => return (CliCmd::Exit, None),
        _ => {}
    }

    (CliCmd::Undefined, None)
}

fn show_help() {
    println!(
        "
<enter key>                                              go to next page.
<TAB Key>                                                commands auto completion.
/b or b                                                  go back to previous page.
/x                                                       exit from label mode.
#<cluster-id>                                            get into the label mode and show defail information of the label.

/event clear                                             clear event filters.
/event regex [!]<pattern>                                filter events in current cluster by regular expression.
/filter label                                            filter qualified clusters by all labels.
/filter label <label-id>                                 filter qualified clusters by the specified label.
/filter count|score >|>=|=|<=|< <value>                  filter clusters by the number of event in cluster or it's score.
/filter qualifier benign|mixed|suspicious|unknown        filter clusters by the manual qualifier of cluster.
/filter regex [!]<pattern>                               filter the events of clusters by regular expression.
/quit or /q                                              quit this program.
/save [force]                                            save or overwrite if force option set.
/set csvstyle on|off                                     set message display style.
/set reverse on|off                                      navigate reverse direction.
/set samples on|off                                      show samples.
/set samplescount <count>                                change sample display count.
/set signature on|off                                    show signature of cluster.
/set tokens on|off                                       show tokens and it's matching result in the cluster.
/set benign|mixed|suspicious|unknown [all]               set qualifier cluster or all clusters of current layer.
/status                                                  show status.
/help or /? or ?                                         show help message.\n"
    );
    // TODO
    // set label <label-id>                               set label to cluster.
    // remove label <label-id> ...                        remove the specified labels.
}
