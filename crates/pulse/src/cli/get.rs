use std::{collections::HashMap, str::FromStr};

use pulsevm_api_client::PulseVmClient;
use pulsevm_api_types::Permission;
use pulsevm_core::{asset::Asset, name::Name};
use pulsevm_keosd_client::KeosdClient;

use crate::cli::GetSubcommand;

pub async fn handle(
    api_client: &PulseVmClient,
    _client: &KeosdClient,
    subcmd: GetSubcommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match subcmd {
        GetSubcommand::Info => {
            let info = api_client.get_info().await?;
            let json = serde_json::to_string_pretty(&info)?;
            println!("{}", json);
        }
        GetSubcommand::Account {
            name,
            expected_core_symbol,
        } => {
            let name = Name::from_str(&name)?;
            let res = api_client.get_account(&name, &expected_core_symbol).await?;
            println!("created: {}", res.created);

            if res.privileged {
                println!("privileged: true");
            }

            println!("permissions:");
            let mut tree: HashMap<Name, Vec<Name>> = HashMap::new();
            let mut roots: Vec<Name> = Vec::new();
            let mut cache: HashMap<Name, Permission> = HashMap::new();

            for perm in res.permissions {
                if !perm.parent.empty() {
                    tree.entry(perm.parent.clone())
                        .or_default()
                        .push(perm.perm_name.clone());
                } else {
                    roots.push(perm.perm_name.clone());
                }
                let name = perm.perm_name.clone();
                cache.insert(name, perm);
            }

            let print_auth = |p: &Permission, depth: usize| {
                let indent_str = " ".repeat(depth * 3);
                print!(
                    "     {}{} {:>5}:    ",
                    indent_str, p.perm_name, p.required_auth.threshold
                );

                let mut sep = "";
                for kw in &p.required_auth.keys {
                    print!("{}{} {}", sep, kw.weight, kw.key.to_string());
                    sep = ", ";
                }
                for acc in &p.required_auth.accounts {
                    print!(
                        "{}{} {}@{}",
                        sep, acc.weight, acc.permission.actor, acc.permission.permission
                    );
                    sep = ", ";
                }
                println!();
            };

            roots.sort();
            for r in &roots {
                dfs_exec(r, 0, &tree, &cache, &print_auth);
            }
            println!();

            println!("permission links:");

            let print_links = |p: &Permission, _depth: usize| {
                if let Some(linked_actions) = &p.linked_actions {
                    if !linked_actions.is_empty() {
                        println!("     {}:", p.perm_name);
                        for la in linked_actions {
                            let action_value = match &la.action {
                                Some(action) => action.to_string(),
                                None => "*".to_string(),
                            };
                            println!("          {}::{}", la.account, action_value);
                        }
                    }
                }
            };

            for r in &roots {
                dfs_exec(r, 0, &tree, &cache, &print_links);
            }

            println!("memory:");
            println!(
                "     quota: {:>15}  used: {:>15}",
                to_pretty_net(res.ram_quota, 5),
                to_pretty_net(res.ram_usage, 5)
            );
            println!();

            println!("net bandwidth:");
            if let Some(current_used) = res.net_limit.current_used {
                println!("     {:<11}{:>18}", "used:", to_pretty_net(current_used, 5));
            } else {
                println!(
                    "     {:<11}{:>18}    ( out of date )",
                    "used:",
                    to_pretty_net(res.net_limit.used, 5)
                );
            }
            println!(
                "     {:<11}{:>18}",
                "available:",
                to_pretty_net(res.net_limit.available, 5)
            );
            println!(
                "     {:<11}{:>18}",
                "limit:",
                to_pretty_net(res.net_limit.max, 5)
            );
            println!();

            println!("cpu bandwidth:");
            if let Some(current_used) = res.cpu_limit.current_used {
                println!("     {:<11}{:>18}", "used:", to_pretty_cpu(current_used, 5));
            } else {
                println!(
                    "     {:<11}{:>18}    ( out of date )",
                    "used:",
                    to_pretty_cpu(res.cpu_limit.used, 5)
                );
            }
            println!(
                "     {:<11}{:>18}",
                "available:",
                to_pretty_cpu(res.cpu_limit.available, 5)
            );
            println!(
                "     {:<11}{:>18}",
                "limit:",
                to_pretty_cpu(res.cpu_limit.max, 5)
            );
            println!();

            if let Some(core_liquid_balance) = &res.core_liquid_balance {
                println!("{} balances:", core_liquid_balance.symbol().code());
                println!("     {:<11}{:>18}", "liquid:", core_liquid_balance);
                println!(
                    "     {:<11}{:>18}",
                    "total:",
                    Asset::new(
                        core_liquid_balance.amount(),
                        core_liquid_balance.symbol().clone()
                    )
                );
                println!();
            }
        }
    }

    Ok(())
}

fn dfs_exec(
    name: &Name,
    depth: usize,
    tree: &HashMap<Name, Vec<Name>>,
    cache: &HashMap<Name, Permission>,
    f: &dyn Fn(&Permission, usize),
) {
    let p = &cache[name];
    f(p, depth);

    if let Some(children) = tree.get(name) {
        let mut sorted = children.clone();
        sorted.sort();
        for child in &sorted {
            dfs_exec(child, depth + 1, tree, cache, f);
        }
    }
}

fn to_pretty_net(nbytes: i64, width_for_units: usize) -> String {
    if nbytes == -1 {
        return "unlimited".to_string();
    }

    let mut bytes = nbytes as f64;
    let unit;

    if bytes >= 1024.0 * 1024.0 * 1024.0 * 1024.0 {
        unit = "TiB";
        bytes /= 1024.0 * 1024.0 * 1024.0 * 1024.0;
    } else if bytes >= 1024.0 * 1024.0 * 1024.0 {
        unit = "GiB";
        bytes /= 1024.0 * 1024.0 * 1024.0;
    } else if bytes >= 1024.0 * 1024.0 {
        unit = "MiB";
        bytes /= 1024.0 * 1024.0;
    } else if bytes >= 1024.0 {
        unit = "KiB";
        bytes /= 1024.0;
    } else {
        unit = "bytes";
    }

    if width_for_units > 0 {
        format!("{:.4} {:<width$}", bytes, unit, width = width_for_units)
    } else {
        format!("{:.4} {}", bytes, unit)
    }
}

fn to_pretty_time(nmicro: i64, width_for_units: usize) -> String {
    if nmicro == -1 {
        return "unlimited".to_string();
    }

    let mut micro = nmicro as f64;
    let unit;

    if micro > 1_000_000.0 * 60.0 * 60.0 {
        micro /= 1_000_000.0 * 60.0 * 60.0;
        unit = "hr";
    } else if micro > 1_000_000.0 * 60.0 {
        micro /= 1_000_000.0 * 60.0;
        unit = "min";
    } else if micro > 1_000_000.0 {
        micro /= 1_000_000.0;
        unit = "sec";
    } else if micro > 1000.0 {
        micro /= 1000.0;
        unit = "ms";
    } else {
        unit = "us";
    }

    if width_for_units > 0 {
        format!("{:.4} {:<width$}", micro, unit, width = width_for_units)
    } else {
        format!("{:.4} {}", micro, unit)
    }
}

fn to_pretty_cpu(nops: i64, width_for_units: usize) -> String {
    if nops == -1 {
        return "unlimited".to_string();
    }

    if width_for_units > 0 {
        format!("{} {:<width$}", nops, "ops", width = width_for_units)
    } else {
        format!("{} {}", nops, "ops")
    }
}
