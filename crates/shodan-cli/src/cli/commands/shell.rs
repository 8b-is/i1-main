//! `showdi1 shell` - Interactive shell mode.

use anyhow::Result;
use colored::Colorize;

use super::Context;

pub async fn execute(ctx: Context) -> Result<()> {
    println!("{}", r#"
 _____ _               _ _  __
|  ___| |__   ___   __| (_) \
| |__ | '_ \ / _ \ / _` | |  |
|__  || | | | (_) | (_| | |  |
|____/|_| |_|\___/ \__,_|_|  |
                          |__|
"#.cyan());

    println!("Welcome to the {} interactive shell!", "Shodan".bold());
    println!("Type {} for commands, {} for tips, {} to quit.",
        "help".green(),
        "tips".yellow(),
        "exit".red()
    );
    println!();

    // Check API key
    if ctx.api_key.is_none() {
        println!("{}", "Warning: No API key set. Set one with: .key <YOUR_KEY>".yellow());
        println!();
    }

    // TODO: Implement full REPL with rustyline
    // For now, just show a message
    println!("{}", "Interactive shell is coming soon!".dimmed());
    println!();
    println!("For now, use individual commands:");
    println!("  {} host 8.8.8.8", "showdi1".cyan());
    println!("  {} search apache --facets country", "showdi1".cyan());
    println!("  {} defend status", "showdi1".cyan());

    Ok(())
}
