//! Shell completion generation for RuZip
//!
//! This module provides functionality to generate shell completion scripts
//! for various shells including Bash, Zsh, Fish, PowerShell, and Elvish.

use crate::error::{Result, RuzipError};
use clap::{Command, CommandFactory};
use clap_complete::{generate, Shell};
use std::io::Write;
use std::path::Path;

/// Generate completion script for the specified shell
pub fn generate_completion<W: Write>(
    shell: Shell,
    writer: &mut W,
    cmd: &mut Command,
    bin_name: &str,
) -> Result<()> {
    generate(shell, cmd, bin_name, writer);
    Ok(())
}

/// Generate completion script to a file
pub fn generate_completion_to_file<P: AsRef<Path>>(
    shell: Shell,
    output_path: P,
    bin_name: &str,
) -> Result<()> {
    let mut cmd = crate::cli::Cli::command();
    let mut file = std::fs::File::create(&output_path)
        .map_err(|e| RuzipError::io_error(
            format!("Failed to create completion file: {}", output_path.as_ref().display()),
            e,
        ))?;
    
    generate_completion(shell, &mut file, &mut cmd, bin_name)?;
    
    tracing::info!(
        "Generated {} completion script: {}",
        shell_name(shell),
        output_path.as_ref().display()
    );
    
    Ok(())
}

/// Get the default installation path for completion scripts
pub fn get_default_completion_path(shell: Shell) -> Option<std::path::PathBuf> {
    use dirs::config_dir;
    
    match shell {
        Shell::Bash => {
            // Try multiple locations for bash completions
            if let Ok(completion_dir) = std::env::var("BASH_COMPLETION_USER_DIR") {
                return Some(std::path::PathBuf::from(completion_dir).join("ruzip"));
            }
            
            // Fallback to user config directory
            config_dir().map(|dir| dir.join("bash_completion").join("ruzip"))
        }
        Shell::Zsh => {
            // Check if we have a zsh fpath
            if let Ok(fpath) = std::env::var("FPATH") {
                if let Some(first_path) = fpath.split(':').next() {
                    return Some(std::path::PathBuf::from(first_path).join("_ruzip"));
                }
            }
            
            // Fallback to user config directory
            config_dir().map(|dir| dir.join("zsh").join("completions").join("_ruzip"))
        }
        Shell::Fish => {
            config_dir().map(|dir| dir.join("fish").join("completions").join("ruzip.fish"))
        }
        Shell::PowerShell => {
            config_dir().map(|dir| dir.join("powershell").join("Microsoft.PowerShell_profile.ps1"))
        }
        Shell::Elvish => {
            config_dir().map(|dir| dir.join("elvish").join("lib").join("ruzip.elv"))
        }
        _ => None,
    }
}

/// Get human-readable shell name
pub fn shell_name(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => "Bash",
        Shell::Zsh => "Zsh",
        Shell::Fish => "Fish",
        Shell::PowerShell => "PowerShell",
        Shell::Elvish => "Elvish",
        _ => "Unknown",
    }
}

/// Install completion script to the default location
pub fn install_completion(shell: Shell, bin_name: &str) -> Result<()> {
    let default_path = get_default_completion_path(shell)
        .ok_or_else(|| RuzipError::config_error(
            "Could not determine default completion path",
            None,
        ))?;
    
    // Create parent directory if it doesn't exist
    if let Some(parent) = default_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| RuzipError::io_error(
                format!("Failed to create completion directory: {}", parent.display()),
                e,
            ))?;
    }
    
    generate_completion_to_file(shell, &default_path, bin_name)?;
    
    println!(
        "Installed {} completion script to: {}",
        shell_name(shell),
        default_path.display()
    );
    
    // Provide installation instructions
    print_installation_instructions(shell, &default_path);
    
    Ok(())
}

/// Print shell-specific installation instructions
fn print_installation_instructions(shell: Shell, path: &Path) {
    match shell {
        Shell::Bash => {
            println!("\nTo enable bash completion, add the following to your ~/.bashrc:");
            println!("    source {}", path.display());
            println!("Or reload your shell: source ~/.bashrc");
        }
        Shell::Zsh => {
            println!("\nTo enable zsh completion, ensure the completion directory is in your fpath.");
            println!("Add the following to your ~/.zshrc if not already present:");
            if let Some(parent) = path.parent() {
                println!("    fpath=(\"{}\" $fpath)", parent.display());
            }
            println!("    autoload -U compinit && compinit");
            println!("Or reload your shell: source ~/.zshrc");
        }
        Shell::Fish => {
            println!("\nFish completions are automatically loaded from the completions directory.");
            println!("Restart your fish shell or run: fish -c 'complete --do-complete=\"ruzip \"'");
        }
        Shell::PowerShell => {
            println!("\nTo enable PowerShell completion, the script has been added to your profile.");
            println!("Restart PowerShell or run: . $PROFILE");
        }
        Shell::Elvish => {
            println!("\nTo enable Elvish completion, add the following to your ~/.elvish/rc.elv:");
            println!("    use {}", path.display());
        }
        _ => {
            println!("\nCompletion script generated at: {}", path.display());
            println!("Please refer to your shell's documentation for installation instructions.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_completion() {
        let mut output = Vec::new();
        let mut cmd = crate::cli::Cli::command();
        
        let result = generate_completion(Shell::Bash, &mut output, &mut cmd, "ruzip");
        assert!(result.is_ok());
        assert!(!output.is_empty());
        
        // Check that the output contains expected bash completion elements
        let completion_text = String::from_utf8(output).unwrap();
        assert!(completion_text.contains("ruzip") || completion_text.contains("_ruzip"));
    }

    #[test]
    fn test_generate_completion_to_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        
        let result = generate_completion_to_file(Shell::Fish, path, "ruzip");
        assert!(result.is_ok());
        
        // Verify file was created and has content
        let content = std::fs::read_to_string(path).unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_shell_name() {
        assert_eq!(shell_name(Shell::Bash), "Bash");
        assert_eq!(shell_name(Shell::Zsh), "Zsh");
        assert_eq!(shell_name(Shell::Fish), "Fish");
        assert_eq!(shell_name(Shell::PowerShell), "PowerShell");
        assert_eq!(shell_name(Shell::Elvish), "Elvish");
    }

    #[test]
    fn test_get_default_completion_path() {
        // Test that we get reasonable paths for different shells
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell, Shell::Elvish] {
            let path = get_default_completion_path(shell);
            // Path might be None in test environment, but shouldn't panic
            if let Some(p) = path {
                assert!(!p.as_os_str().is_empty());
            }
        }
    }
}