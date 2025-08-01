use anyhow::Result;
use tokio::sync::mpsc::{self, UnboundedSender};
use crate::decoder;
use crate::settings::{DisplayType, UserConfig};
use crate::visualizer::{Visualizer, BLACKLIST, SHOW, WHITELIST};

/// Reads from the standard input.
pub fn start() -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();

    std::thread::Builder::new()
        .name("Console reader".to_string())
        .spawn(|| start_reading(tx))?;

    tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            if let Err(error) = handle_command(command).await {
                warn!("Failed to handle command: {}", error);
            }
        }
    });

    Ok(())
}

/// Reads the standard input.
/// tx: The channel to send commands to.
fn start_reading(tx: UnboundedSender<String>) {
    loop {
        let stdin = std::io::stdin();
        let mut buffer = String::new();

        match stdin.read_line(&mut buffer) {
            Ok(_) => {
                let message = buffer.trim().to_string();
                if message.is_empty() {
                    continue;
                }

                if let Err(err) = tx.send(message) {
                    warn!("Failed to send command to channel: {}", err);
                    break;
                }
            }
            Err(err) => {
                warn!("Failed to read from console: {}", err);
                break;
            }
        }
    }
}

/// Handles commands from the standard input.
async fn handle_command(command: String) -> Result<()> {
    // Split the command into arguments.
    let mut args = command
        .split_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    let label = args.remove(0);

    match label.as_str() {
        "clear" => {
            *SHOW.lock().await = DisplayType::All;
            WHITELIST.lock().await.clear();
            BLACKLIST.lock().await.clear();
            info!("Cleared all filters and display settings.");
        },
        "save" => {
            let settings = UserConfig {
                display: SHOW.lock().await.clone(),
                whitelist: WHITELIST.lock().await.clone(),
                blacklist: BLACKLIST.lock().await.clone(),
            };
            settings.save();

            info!("Wrote settings to `config.json`.");
        },
        "reload" => {
            decoder::load_definitions()?;
            Visualizer::load_settings().await;

            info!("Finished reloading.");
        },
        "whitelist" => {
            match args.get(0).map(String::as_str) {
                Some("show") => {
                    *SHOW.lock().await = DisplayType::Whitelist;
                    info!("Now only showing whitelisted packets.");
                },
                Some("list") => {
                    let whitelist = WHITELIST.lock().await;
                    if whitelist.is_empty() {
                        info!("Whitelist is empty.");
                    } else {
                        info!("Whitelisted packets: {}", whitelist.join(", "));
                    }
                },
                Some("add") if args.len() == 2 => {
                    let name = &args[1];
                    let Some(name) = decoder::name_or_id(name) else {
                        warn!("Invalid name or ID '{name}'.");
                        return Ok(())
                    };

                    let mut whitelist = WHITELIST.lock().await;
                    if whitelist.contains(&name) {
                        warn!("Packet '{}' is already whitelisted.", name);
                    } else {
                        whitelist.push(name.clone());
                        info!("Added '{}' to the whitelist.", name);
                    }
                },
                Some("remove") if args.len() == 2 => {
                    let name = &args[1];
                    let Some(name) = decoder::name_or_id(name) else {
                        warn!("Invalid name or ID '{name}'.");
                        return Ok(())
                    };

                    let mut whitelist = WHITELIST.lock().await;
                    whitelist.retain(|x| x != &name);

                    info!("Removed '{}' from the whitelist.", name);
                },
                Some("clear") => {
                    WHITELIST.lock().await.clear();
                    info!("Cleared the whitelist.");
                },
                _ => {
                    warn!("No arguments provided for whitelist command.");
                    info!("Usage: whitelist <show|list|add|remove|clear> [<name|id>]");
                }
            }
        },
        "blacklist" => {
            match args.get(0).map(String::as_str) {
                Some("show") => {
                    *SHOW.lock().await = DisplayType::Blacklist;
                    info!("Now only showing blacklisted packets.");
                },
                Some("list") => {
                    let blacklist = BLACKLIST.lock().await;
                    if blacklist.is_empty() {
                        info!("Blacklist is empty.");
                    } else {
                        info!("Blacklisted packets: {}", blacklist.join(", "));
                    }
                },
                Some("add") if args.len() == 2 => {
                    let name = &args[1];
                    let Some(name) = decoder::name_or_id(name) else {
                        warn!("Invalid name or ID '{name}'.");
                        return Ok(())
                    };

                    let mut blacklist = BLACKLIST.lock().await;
                    if blacklist.contains(&name) {
                        warn!("Packet '{}' is already blacklisted.", name);
                    } else {
                        blacklist.push(name.clone());
                        info!("Added '{}' to the blacklist.", name);
                    }
                },
                Some("remove") if args.len() == 2 => {
                    let name = &args[1];
                    let Some(name) = decoder::name_or_id(name) else {
                        warn!("Invalid name or ID '{name}'.");
                        return Ok(())
                    };

                    let mut blacklist = BLACKLIST.lock().await;
                    blacklist.retain(|x| x != &name);

                    info!("Removed '{}' from the blacklist.", name);
                },
                Some("clear") => {
                    BLACKLIST.lock().await.clear();
                    info!("Cleared the blacklist.");
                },
                _ => {
                    warn!("No arguments provided for blacklist command.");
                    info!("Usage: blacklist <show|list|add|remove|clear> [<name|id>]");
                }
            }
        },
        _ => {
            warn!("Unknown command: {}", label);
            info!("Known commands: clear, save, reload, whitelist, blacklist")
        }
    }

    Ok(())
}