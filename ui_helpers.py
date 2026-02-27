"""
UI Helper Functions
Common utilities for CLI and GUI interfaces
"""
import os
import sys
import time
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from datetime import datetime

# Rich imports for beautiful CLI
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

console = Console()

def print_banner():
    """Print application banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   🔐 QKD MULTIMODAL SECURE COMMUNICATION SYSTEM 🔐           ║
    ║                                                               ║
    ║   Quantum Key Distribution + Biometric Authentication         ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold blue", box=box.DOUBLE))

def print_status(message: str, style: str = "info"):
    """Print status message with icon"""
    icons = {
        "info": "ℹ️",
        "success": "✅",
        "warning": "⚠️",
        "error": "❌",
        "lock": "🔒",
        "key": "🔑",
        "face": "👤",
        "fingerprint": "🖐️"
    }
    icon = icons.get(style, "•")
    console.print(f"{icon} {message}")

def print_section(title: str):
    """Print section header"""
    console.print("[bold cyan]" + "="*60 + "[/bold cyan]")
    console.print("[bold cyan]" + title.center(60) + "[/bold cyan]")
    console.print("[bold cyan]" + "="*60 + "[/bold cyan]")

def create_progress_spinner(description: str):
    """Create a progress spinner"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    )

def print_auth_result(result: Dict[str, Any]):
    """Print authentication result in a table"""
    table = Table(title="Authentication Result", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Success", "✅ Yes" if result.get('success') else "❌ No")
    table.add_row("Face Verified", "✅" if result.get('face_verified') else "❌")
    table.add_row("Fingerprint Verified", "✅" if result.get('fingerprint_verified') else "❌")
    table.add_row("Face Confidence", f"{result.get('face_confidence', 0):.2%}")
    table.add_row("Fingerprint Confidence", f"{result.get('fingerprint_confidence', 0):.2%}")
    table.add_row("Session ID", result.get('session_id', 'N/A')[:16] + "...")

    console.print(table)

def print_encryption_result(metadata: Dict[str, Any]):
    """Print encryption result"""
    table = Table(title="Encryption Details", box=box.ROUNDED)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Original File", metadata.get('original_name', 'N/A'))
    table.add_row("Original Size", f"{metadata.get('original_size', 0) / 1024:.2f} KB")
    table.add_row("Compressed", "Yes" if metadata.get('compressed') else "No")
    table.add_row("Algorithm", "AES-256-GCM")
    table.add_row("Key Source", "QKD + Face + Fingerprint")

    console.print(table)

def confirm_action(message: str) -> bool:
    """Ask for confirmation"""
    response = console.input(f"{message} [y/N]: ").lower()
    return response in ['y', 'yes']

def print_menu(options: Dict[str, str], title: str = "Menu"):
    """Print interactive menu"""
    console.print("[bold]" + title + ":[/bold]")
    for key, value in options.items():
        console.print("  [" + key + "] " + value)
    console.print()

def get_menu_choice(options: Dict[str, str], prompt: str = "Select option") -> str:
    """Get menu choice from user"""
    while True:
        print_menu(options)
        choice = console.input(f"{prompt}: ").strip()
        if choice in options:
            return choice
        console.print("[red]Invalid choice. Please try again.[/red]")

def format_bytes(size: int) -> str:
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"

def print_file_info(file_path: Path):
    """Print file information"""
    if not file_path.exists():
        console.print(f"[red]File not found: {file_path}[/red]")
        return

    stat = file_path.stat()
    table = Table(box=box.SIMPLE)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Name", file_path.name)
    table.add_row("Size", format_bytes(stat.st_size))
    table.add_row("Modified", datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"))
    table.add_row("Type", "Encrypted" if file_path.suffix == '.enc' else "Plain")

    console.print(table)

def countdown(seconds: int, message: str = "Starting in"):
    """Simple countdown timer"""
    for i in range(seconds, 0, -1):
        console.print(f"{message} {i}...", end="\r")
        time.sleep(1)
    console.print(" " * 50, end="\r")

def print_security_warning():
    """Print security warning"""
    warning = """
    [yellow]⚠️  SECURITY NOTICE:[/yellow]

    This system uses:
    • BB84 Quantum Key Distribution (simulated)
    • AES-256-GCM authenticated encryption
    • Biometric authentication (Face + Fingerprint)

    [red]Important:[/red]
    • Keep your biometric templates secure
    • Do not share your session IDs
    • Verify recipient identity before sharing encrypted files
    • This is a demonstration system - not for production use
    """
    console.print(Panel(warning, style="yellow", box=box.ROUNDED))

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def pause():
    """Pause for user input"""
    console.input("\n[Press Enter to continue...]")