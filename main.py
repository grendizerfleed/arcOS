#!/usr/bin/env python3
"""
ArcOS - Secure Portable Operating System
Authentication-required environment with real package management
"""

import os
import sys
import hashlib
import getpass
import json
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import base64
import tempfile
import shlex
import urllib.request
import urllib.parse
import importlib.metadata

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich import print as rprint

class ArcOSSecurity:
    """Security subsystem for ArcOS"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password with salt using PBKDF2"""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.b64encode(salt + key).decode()
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            decoded = base64.b64decode(hashed.encode())
            salt, stored_key = decoded[:32], decoded[32:]
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            return stored_key == key
        except:
            return False
    
    @staticmethod
    def sanitize_path(user_path: str, current_dir: str, root_dir: str) -> Optional[Path]:
        """Sanitize and validate file paths to prevent directory traversal"""
        try:
            # Convert to absolute path within ArcOS filesystem
            if user_path.startswith('/'):
                abs_path = Path(root_dir) / user_path.lstrip('/')
            else:
                abs_path = Path(root_dir) / current_dir.lstrip('/') / user_path
            
            # Resolve and ensure it stays within ArcOS root
            abs_path = abs_path.resolve()
            root_path = Path(root_dir).resolve()
            
            # Check if path is within ArcOS root
            if root_path in abs_path.parents or abs_path == root_path:
                return abs_path
            return None
        except:
            return None

class ArcOSFilesystem:
    """Virtual filesystem for ArcOS with authentication checks"""
    
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.root = data_dir / "arcos_root"
        self.root.mkdir(parents=True, exist_ok=True)
        self.arcos_system = None  # Will be set by ArcOS class
        self.initialize_filesystem()
    
    def initialize_filesystem(self):
        """Create basic directory structure"""
        dirs = [
            "/bin", "/etc", "/home", "/tmp", "/var", "/proc",
            "/usr/bin", "/usr/lib", "/usr/share", "/usr/local",
            "/var/log", "/var/cache", "/var/lib/arcos",
            "/opt", "/mnt", "/srv"
        ]
        
        for dir_path in dirs:
            (self.root / dir_path.lstrip('/')).mkdir(parents=True, exist_ok=True)
        
        # Create basic configuration files
        self.create_file("/etc/os-release", """NAME="ArcOS"
VERSION="4.0.0"
ID=arcos
PRETTY_NAME="ArcOS Secure Environment"
HOME_URL="https://github.com/arcos-project"
BUG_REPORT_URL="https://github.com/arcos-project/issues"
""")
        
        self.create_file("/etc/motd", """
╔═══════════════════════════════════════════════╗
║                WELCOME TO ARCOS               ║
║           Secure Portable Environment         ║
║                                               ║
║        🔐 Authentication Required            ║
║        📁 Protected Filesystem               ║
║        🚀 Real Package Management            ║
║   Type 'help' for available commands          ║
╚═══════════════════════════════════════════════╝
""")
        
        # Create user home directories
        (self.root / "home/user").mkdir(parents=True, exist_ok=True)
        (self.root / "root").mkdir(parents=True, exist_ok=True)
    
    def create_file(self, path: str, content: str = "") -> bool:
        """Create a file in the virtual filesystem"""
        full_path = self.root / path.lstrip('/')
        try:
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
            if '/bin/' in path or path.startswith('/usr/local/bin/'):
                full_path.chmod(0o755)
            return True
        except:
            return False
    
    def read_file(self, path: str) -> Optional[str]:
        """Read a file from the virtual filesystem (requires authentication)"""
        if not self.arcos_system or not self.arcos_system.current_user:
            return None
            
        full_path = self.root / path.lstrip('/')
        try:
            return full_path.read_text()
        except:
            return None
    
    def list_directory(self, path: str) -> Optional[List[Dict]]:
        """List directory contents (requires authentication)"""
        if not self.arcos_system or not self.arcos_system.current_user:
            return None
            
        full_path = self.root / path.lstrip('/')
        try:
            items = []
            for item in full_path.iterdir():
                stat = item.stat()
                items.append({
                    'name': item.name,
                    'type': 'directory' if item.is_dir() else 'file',
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime),
                    'executable': os.access(item, os.X_OK)
                })
            return sorted(items, key=lambda x: (x['type'] != 'directory', x['name']))
        except:
            return None
    
    def path_exists(self, path: str) -> bool:
        """Check if path exists in virtual filesystem"""
        full_path = self.root / path.lstrip('/')
        return full_path.exists()
    
    def is_directory(self, path: str) -> bool:
        """Check if path is a directory"""
        full_path = self.root / path.lstrip('/')
        return full_path.is_dir()

class ArcOSUserManager:
    """User management system"""
    
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.users_file = data_dir / "users.json"
        self.users = {}
        self.load_users()
    
    def load_users(self):
        """Load users from storage"""
        if self.users_file.exists():
            try:
                self.users = json.loads(self.users_file.read_text())
            except:
                self.users = {}
        else:
            self.users = {}
    
    def save_users(self):
        """Save users to storage"""
        self.users_file.write_text(json.dumps(self.users, indent=2))
    
    def create_user(self, username: str, password: str, uid: int, description: str = "") -> bool:
        """Create a new user"""
        if username in self.users:
            return False
        
        self.users[username] = {
            'uid': uid,
            'password_hash': ArcOSSecurity.hash_password(password),
            'description': description,
            'home_dir': f"/home/{username}",
            'shell': "/bin/arcsh",
            'created': datetime.now().isoformat()
        }
        self.save_users()
        return True
    
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate user"""
        if username not in self.users:
            return False
        return ArcOSSecurity.verify_password(password, self.users[username]['password_hash'])
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """Get user information"""
        return self.users.get(username)

class ArcOSPackageManager:
    """Real package management with PyPI queries and actual installations"""
    
    def __init__(self, fs: ArcOSFilesystem):
        self.fs = fs
        self.pip_packages = {}
        self.git_repos = {}
        self.load_packages()
    
    def load_packages(self):
        """Load installed packages from storage"""
        packages_data = self.fs.read_file("/var/lib/arcos/packages.json")
        if packages_data:
            try:
                data = json.loads(packages_data)
                self.pip_packages = data.get('pip_packages', {})
                self.git_repos = data.get('git_repos', {})
            except:
                self.pip_packages = {}
                self.git_repos = {}
    
    def save_packages(self):
        """Save installed packages to storage"""
        data = {
            'pip_packages': self.pip_packages,
            'git_repos': self.git_repos
        }
        self.fs.create_file("/var/lib/arcos/packages.json", json.dumps(data, indent=2))
    
    def search_pypi_package(self, query: str) -> Tuple[bool, List[Dict]]:
        """Search for packages on PyPI using the JSON API"""
        try:
            url = f"https://pypi.org/pypi?q={urllib.parse.quote(query)}"
            
            with urllib.request.urlopen(url) as response:
                data = json.loads(response.read().decode())
                
            results = []
            for package in data.get('projects', []):
                results.append({
                    'name': package.get('name', ''),
                    'version': package.get('version', ''),
                    'description': package.get('description', '')[:200] + '...' if package.get('description') else 'No description',
                })
            
            return True, results[:10]
            
        except Exception as e:
            return False, [f"Error searching PyPI: {str(e)}"]
    
    def get_package_info(self, package_name: str) -> Tuple[bool, Dict]:
        """Get detailed information about a package from PyPI"""
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            
            with urllib.request.urlopen(url) as response:
                data = json.loads(response.read().decode())
            
            info = data.get('info', {})
            return True, {
                'name': info.get('name', ''),
                'version': info.get('version', ''),
                'summary': info.get('summary', ''),
                'description': info.get('description', ''),
                'author': info.get('author', ''),
                'license': info.get('license', ''),
                'home_page': info.get('home_page', ''),
                'requires_python': info.get('requires_python', ''),
                'requires_dist': info.get('requires_dist', [])
            }
        except Exception as e:
            return False, {'error': f"Error fetching package info: {str(e)}"}
    
    def install_pip_package(self, package_name: str, version: str = None) -> Tuple[bool, str]:
        """Actually install a Python package using pip"""
        try:
            if package_name in self.pip_packages:
                return False, f"{package_name} already installed"
            
            install_cmd = [sys.executable, "-m", "pip", "install"]
            if version:
                package_spec = f"{package_name}=={version}"
            else:
                package_spec = package_name
            
            install_cmd.append(package_spec)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                transient=True,
            ) as progress:
                progress.add_task(f"Installing {package_spec}...", total=None)
                
                result = subprocess.run(
                    install_cmd,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    return False, f"Installation failed: {result.stderr}"
                
                try:
                    installed_pkg = importlib.metadata.distribution(package_name)
                    version = installed_pkg.version
                    metadata = installed_pkg.metadata
                    
                    self.pip_packages[package_name] = {
                        "version": version,
                        "summary": metadata.get('Summary', ''),
                        "author": metadata.get('Author', ''),
                        "license": metadata.get('License', ''),
                        "home_page": metadata.get('Home-page', ''),
                        "installed_at": datetime.now().isoformat(),
                        "type": "pip"
                    }
                    
                    self.save_packages()
                    return True, f"Successfully installed {package_name}=={version}"
                    
                except importlib.metadata.PackageNotFoundError:
                    self.pip_packages[package_name] = {
                        "version": "unknown",
                        "installed_at": datetime.now().isoformat(),
                        "type": "pip"
                    }
                    self.save_packages()
                    return True, f"Installed {package_name} (metadata unavailable)"
                
        except Exception as e:
            return False, f"Error installing {package_name}: {str(e)}"
    
    def uninstall_pip_package(self, package_name: str) -> Tuple[bool, str]:
        """Actually uninstall a Python package using pip"""
        try:
            if package_name not in self.pip_packages:
                return False, f"{package_name} is not installed"
            
            result = subprocess.run(
                [sys.executable, "-m", "pip", "uninstall", "-y", package_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                del self.pip_packages[package_name]
                self.save_packages()
                return True, f"Successfully uninstalled {package_name}"
            else:
                return False, f"Uninstall failed: {result.stderr}"
                
        except Exception as e:
            return False, f"Error uninstalling {package_name}: {str(e)}"
    
    def install_git_repo(self, repo_url: str, target_dir: str = None) -> Tuple[bool, str]:
        """Actually clone a git repository"""
        try:
            repo_name = repo_url.split('/')[-1]
            if repo_name.endswith('.git'):
                repo_name = repo_name[:-4]
            
            if target_dir is None:
                target_dir = f"/opt/{repo_name}"
            
            if repo_url in self.git_repos:
                return False, f"Repository {repo_url} already installed"
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                transient=True,
            ) as progress:
                progress.add_task(f"Cloning {repo_name}...", total=None)
                
                clone_path = self.fs.root / target_dir.lstrip('/')
                clone_path.mkdir(parents=True, exist_ok=True)
                
                result = subprocess.run(
                    ['git', 'clone', '--depth', '1', repo_url, str(clone_path)],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    return False, f"Git clone failed: {result.stderr}"
                
                self.git_repos[repo_url] = {
                    "name": repo_name,
                    "path": target_dir,
                    "url": repo_url,
                    "type": "git",
                    "cloned_at": datetime.now().isoformat()
                }
                
                self.save_packages()
                return True, f"Successfully cloned {repo_url} to {target_dir}"
                
        except Exception as e:
            return False, f"Error cloning repository: {str(e)}"
    
    def list_installed_packages(self) -> Dict[str, List]:
        """Get all installed packages"""
        pip_pkgs = list(self.pip_packages.keys())
        git_repos = list(self.git_repos.keys())
        
        return {
            'pip': pip_pkgs,
            'git': git_repos
        }
    
    def get_package_details(self, package_name: str) -> Optional[Dict]:
        """Get detailed information about an installed package"""
        if package_name in self.pip_packages:
            return self.pip_packages[package_name]
        return None

class ArcOSCommandExecutor:
    """Command executor with authentication requirements"""
    
    def __init__(self, arcos_system):
        self.arcos = arcos_system
        self.console = arcos_system.console
    
    def check_authentication(self) -> bool:
        """Check if user is authenticated"""
        if not self.arcos.current_user:
            self.console.print("❌ Authentication required. Please login first.", style="red")
            return False
        return True
    
    def execute_command(self, command_line: str) -> bool:
        """Execute command with authentication check"""
        if not command_line.strip():
            return True
        
        parts = command_line.split()
        command = parts[0]
        args = parts[1:]
        
        # Public commands (no authentication required)
        if command == "login":
            return self.handle_login(args)
        elif command == "help":
            return self.handle_help(args)
        elif command == "exit":
            return self.handle_exit(args)
        
        # All other commands require authentication
        if not self.check_authentication():
            return True
        
        # Authenticated commands
        if command == "logout":
            return self.handle_logout(args)
        elif command == "whoami":
            return self.handle_whoami(args)
        elif command == "pwd":
            return self.handle_pwd(args)
        elif command == "ls":
            return self.handle_ls(args)
        elif command == "cd":
            return self.handle_cd(args)
        elif command == "cat":
            return self.handle_cat(args)
        elif command == "mkdir":
            return self.handle_mkdir(args)
        elif command == "touch":
            return self.handle_touch(args)
        elif command == "pip":
            return self.handle_pip(args)
        elif command == "git":
            return self.handle_git(args)
        elif command == "clear":
            return self.handle_clear(args)
        else:
            # External command execution (requires auth)
            return self.execute_external_command(command_line)
    
    def execute_external_command(self, command_line: str) -> bool:
        """Execute an external command (requires authentication)"""
        if not self.check_authentication():
            return True
            
        try:
            parts = shlex.split(command_line)
            if not parts:
                return True
            
            command = parts[0]
            args = parts[1:]
            
            # Try system command first
            cmd_path = shutil.which(command)
            if cmd_path:
                result = subprocess.run(
                    [cmd_path] + args,
                    capture_output=True,
                    text=True,
                    cwd=str(self.arcos.filesystem.root / self.arcos.current_dir.lstrip('/'))
                )
                
                if result.stdout:
                    self.console.print(result.stdout, style="green")
                if result.stderr:
                    self.console.print(result.stderr, style="yellow")
                
                return True
            
            # Try Python module
            result = subprocess.run(
                [sys.executable, "-m", command] + args,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 or result.stdout or result.stderr:
                if result.stdout:
                    self.console.print(result.stdout, style="green")
                if result.stderr:
                    self.console.print(result.stderr, style="yellow")
                return True
            
            # Command not found
            self.console.print(f"❌ Command not found: {command}", style="red")
            return True
            
        except Exception as e:
            self.console.print(f"❌ Error executing command: {e}", style="red")
            return True
    
    def handle_login(self, args) -> bool:
        """Handle login command"""
        if len(args) < 1:
            self.console.print("Usage: login <username>", style="yellow")
            return True
        
        if self.arcos.current_user:
            self.console.print("❌ Already logged in. Use 'logout' first.", style="red")
            return True
        
        username = args[0]
        password = getpass.getpass("Password: ")
        
        if self.arcos.users.authenticate(username, password):
            self.arcos.current_user = username
            user_info = self.arcos.users.get_user_info(username)
            self.arcos.current_dir = user_info['home_dir']
            
            # Show MOTD
            motd = self.arcos.filesystem.read_file("/etc/motd")
            if motd:
                self.console.print(Panel(motd, style="green"))
            
            self.console.print(f"✅ Welcome to ArcOS, {username}!", style="green")
            self.arcos.shell.update_prompt()
            
            # Show system status
            status_panel = Panel(
                f"🔐 Authentication: [green]Granted[/green]\n"
                f"👤 User: [cyan]{username}[/cyan]\n"
                f"📁 Current directory: [blue]{self.arcos.current_dir}[/blue]\n"
                f"🚀 System access: [green]Enabled[/green]",
                title="Authentication Successful",
                style="green"
            )
            self.console.print(status_panel)
            return True
        else:
            self.console.print("❌ Login incorrect", style="red")
            return True
    
    def handle_logout(self, args) -> bool:
        """Handle logout command"""
        self.console.print(f"👋 Goodbye, {self.arcos.current_user}!", style="yellow")
        self.arcos.current_user = None
        self.arcos.current_dir = "/"
        self.arcos.shell.update_prompt()
        
        # Show logout status
        status_panel = Panel(
            f"🔐 Authentication: [red]Required[/red]\n"
            f"📁 Filesystem access: [red]Locked[/red]\n"
            f"🚀 Command execution: [yellow]Limited[/yellow]",
            title="Logged Out",
            style="yellow"
        )
        self.console.print(status_panel)
        return True
    
    def handle_whoami(self, args) -> bool:
        """Handle whoami command"""
        self.console.print(f"👤 {self.arcos.current_user}", style="blue")
        return True
    
    def handle_pwd(self, args) -> bool:
        """Handle pwd command"""
        self.console.print(f"📁 {self.arcos.current_dir}", style="blue")
        return True
    
    def handle_ls(self, args) -> bool:
        """Handle ls command"""
        path = args[0] if args else "."
        
        abs_path = ArcOSSecurity.sanitize_path(path, self.arcos.current_dir, str(self.arcos.filesystem.root))
        if not abs_path:
            self.console.print("❌ Invalid path", style="red")
            return True
        
        rel_path = str(abs_path.relative_to(self.arcos.filesystem.root))
        items = self.arcos.filesystem.list_directory(rel_path)
        if items is None:
            self.console.print("❌ Directory not found or access denied", style="red")
            return True
        
        if not items:
            self.console.print("📁 Directory is empty", style="yellow")
            return True
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Type", width=8)
        table.add_column("Name", style="cyan")
        table.add_column("Size", justify="right")
        table.add_column("Modified")
        
        for item in items:
            icon = "📁" if item['type'] == 'directory' else "📄"
            if item.get('executable'):
                icon = "⚡"
            size = f"{item['size']:,} B" if item['type'] == 'file' else "-"
            table.add_row(
                icon,
                item['name'],
                size,
                item['modified'].strftime("%Y-%m-%d %H:%M")
            )
        
        self.console.print(table)
        return True
    
    def handle_cd(self, args) -> bool:
        """Handle cd command"""
        path = args[0] if args else "~"
        
        if path == "~":
            if self.arcos.current_user:
                user_info = self.arcos.users.get_user_info(self.arcos.current_user)
                path = user_info['home_dir']
            else:
                path = "/"
        
        abs_path = ArcOSSecurity.sanitize_path(path, self.arcos.current_dir, str(self.arcos.filesystem.root))
        if not abs_path:
            self.console.print("❌ Invalid path", style="red")
            return True
        
        rel_path = str(abs_path.relative_to(self.arcos.filesystem.root))
        if not self.arcos.filesystem.is_directory(rel_path):
            self.console.print("❌ Not a directory", style="red")
            return True
        
        self.arcos.current_dir = "/" + rel_path
        self.arcos.shell.update_prompt()
        return True
    
    def handle_cat(self, args) -> bool:
        """Handle cat command"""
        if not args:
            self.console.print("Usage: cat <file>", style="yellow")
            return True
        
        abs_path = ArcOSSecurity.sanitize_path(args[0], self.arcos.current_dir, str(self.arcos.filesystem.root))
        if not abs_path:
            self.console.print("❌ Invalid path", style="red")
            return True
        
        rel_path = str(abs_path.relative_to(self.arcos.filesystem.root))
        content = self.arcos.filesystem.read_file(rel_path)
        if content is None:
            self.console.print("❌ File not found or access denied", style="red")
            return True
        
        self.console.print(Panel(content, title=f"📄 {args[0]}", style="blue"))
        return True
    
    def handle_mkdir(self, args) -> bool:
        """Handle mkdir command"""
        if not args:
            self.console.print("Usage: mkdir <directory>", style="yellow")
            return True
        
        abs_path = ArcOSSecurity.sanitize_path(args[0], self.arcos.current_dir, str(self.arcos.filesystem.root))
        if not abs_path:
            self.console.print("❌ Invalid path", style="red")
            return True
        
        try:
            abs_path.mkdir(parents=True, exist_ok=False)
            self.console.print(f"✅ Created directory {args[0]}", style="green")
            return True
        except FileExistsError:
            self.console.print("❌ Directory already exists", style="red")
            return True
        except:
            self.console.print("❌ Failed to create directory", style="red")
            return True
    
    def handle_touch(self, args) -> bool:
        """Handle touch command"""
        if not args:
            self.console.print("Usage: touch <file>", style="yellow")
            return True
        
        abs_path = ArcOSSecurity.sanitize_path(args[0], self.arcos.current_dir, str(self.arcos.filesystem.root))
        if not abs_path:
            self.console.print("❌ Invalid path", style="red")
            return True
        
        try:
            abs_path.touch(exist_ok=True)
            self.console.print(f"✅ Created file {args[0]}", style="green")
            return True
        except:
            self.console.print("❌ Failed to create file", style="red")
            return True
    
    def handle_pip(self, args) -> bool:
        """Handle pip commands"""
        if not args:
            self.console.print("Usage: pip [install|uninstall|search|info|list] [package]", style="yellow")
            return True
    
        if args[0] == "install" and len(args) > 1:
            package_spec = args[1]
            if '==' in package_spec:
                package_name, version = package_spec.split('==', 1)
            else:
                package_name, version = package_spec, None
        
            success, message = self.arcos.packages.install_pip_package(package_name, version)
            style = "green" if success else "red"
            self.console.print(f"{'✅' if success else '❌'} {message}", style=style)
            return True
    
        elif args[0] == "uninstall" and len(args) > 1:
            package_name = args[1]
            success, message = self.arcos.packages.uninstall_pip_package(package_name)
            style = "green" if success else "red"
            self.console.print(f"{'✅' if success else '❌'} {message}", style=style)
            return True
    
        elif args[0] == "search" and len(args) > 1:
            query = args[1]
            success, results = self.arcos.packages.search_pypi_package(query)
        
            if success:
                if results:
                    table = Table(title=f"PyPI Search Results for '{query}'", show_header=True, header_style="bold green")
                    table.add_column("Package", style="cyan")
                    table.add_column("Version", style="yellow")
                    table.add_column("Description")
                
                    for pkg in results:
                        table.add_row(
                            pkg['name'],
                            pkg.get('version', 'N/A'),
                            pkg['description']
                        )
                    self.console.print(table)
                else:
                    self.console.print(f"❌ No packages found matching '{query}'", style="yellow")
            else:
                self.console.print(f"❌ Search failed: {results[0]}", style="red")
            return True
    
        elif args[0] == "info" and len(args) > 1:
            package_name = args[1]
            success, info = self.arcos.packages.get_package_info(package_name)
        
            if success:
                panel_content = f"""
[bold]Name:[/bold] {info['name']}
[bold]Version:[/bold] {info['version']}
[bold]Summary:[/bold] {info['summary']}
[bold]Author:[/bold] {info['author']}
[bold]License:[/bold] {info['license']}
[bold]Home Page:[/bold] {info['home_page']}
[bold]Python Required:[/bold] {info['requires_python'] or 'Any'}
"""
                if info.get('requires_dist'):
                    panel_content += f"[bold]Dependencies:[/bold]\n"
                    for dep in info['requires_dist']:
                        panel_content += f"  - {dep}\n"
            
                self.console.print(Panel(panel_content, title=f"📦 {package_name} Info", style="blue"))
            else:
                self.console.print(f"❌ {info.get('error', 'Failed to get package info')}", style="red")
            return True
    
        elif args[0] == "list":
            installed = self.arcos.packages.list_installed_packages()
        
            if installed['pip']:
                table = Table(title="Installed Python Packages", show_header=True, header_style="bold green")
                table.add_column("Package", style="cyan")
                table.add_column("Version")
                table.add_column("Installed")
            
                for pkg in installed['pip']:
                    details = self.arcos.packages.get_package_details(pkg)
                    version = details.get('version', 'unknown') if details else 'unknown'
                    installed_at = details.get('installed_at', 'unknown')[:10] if details else 'unknown'
                    table.add_row(pkg, version, installed_at)
                self.console.print(table)
            else:
                self.console.print("No Python packages installed", style="yellow")
            return True
    
        else:
            # Pass through to system pip
            try:
                result = subprocess.run(['pip'] + args, capture_output=True, text=True)
                if result.returncode == 0:
                    self.console.print(result.stdout, style="green")
                else:
                    self.console.print(result.stderr, style="red")
            except Exception as e:
                self.console.print(f"❌ Pip error: {str(e)}", style="red")
            return True

    def handle_git(self, args) -> bool:
        """Handle git commands"""
        if not args:
            self.console.print("Usage: git [clone|list] [repository]", style="yellow")
            return True
        
        if args[0] == "clone" and len(args) > 1:
            repo_url = args[1]
            target_dir = args[2] if len(args) > 2 else None
            
            success, message = self.arcos.packages.install_git_repo(repo_url, target_dir)
            style = "green" if success else "red"
            self.console.print(f"{'✅' if success else '❌'} {message}", style=style)
            return True
        
        elif args[0] == "list":
            installed = self.arcos.packages.list_installed_packages()
            
            if installed['git']:
                table = Table(title="Cloned Git Repositories", show_header=True, header_style="bold yellow")
                table.add_column("Repository", style="cyan")
                table.add_column("Path")
                table.add_column("Cloned At")
                
                for repo_url in installed['git']:
                    info = self.arcos.packages.git_repos.get(repo_url, {})
                    table.add_row(
                        info.get('name', repo_url),
                        info.get('path', 'unknown'),
                        info.get('cloned_at', 'unknown')[:10]
                    )
                self.console.print(table)
            else:
                self.console.print("No git repositories cloned", style="yellow")
            return True
        
        else:
            # Pass through to system git
            try:
                result = subprocess.run(['git'] + args, capture_output=True, text=True)
                if result.returncode == 0:
                    self.console.print(result.stdout, style="green")
                else:
                    self.console.print(result.stderr, style="red")
            except Exception as e:
                self.console.print(f"❌ Git error: {str(e)}", style="red")
            return True
    
    def handle_clear(self, args) -> bool:
        """Handle clear command"""
        self.console.clear()
        return True
    
    def handle_help(self, args) -> bool:
        """Handle help command"""
        if self.arcos.current_user:
            # Authenticated user help
            commands_info = [
                ("logout", "Logout from current session"),
                ("whoami", "Show current user"),
                ("pwd", "Print working directory"),
                ("ls [path]", "List directory contents"),
                ("cd [path]", "Change directory"),
                ("cat <file>", "Display file contents"),
                ("mkdir <dir>", "Create directory"),
                ("touch <file>", "Create empty file"),
                ("pip install <pkg>", "Install Python package from PyPI"),
                ("pip uninstall <pkg>", "Uninstall Python package"),
                ("pip search <query>", "Search PyPI for packages"),
                ("pip info <pkg>", "Get package information from PyPI"),
                ("pip list", "List installed packages"),
                ("git clone <url>", "Clone git repository"),
                ("git list", "List cloned repositories"),
                ("clear", "Clear screen"),
                ("help", "Show this help"),
                ("exit", "Exit ArcOS"),
                ("[any command]", "Run external command")
            ]
            
            status = "[green]Authenticated[/green]"
            access_level = "[green]Full System Access[/green]"
        else:
            # Unauthenticated user help
            commands_info = [
                ("login <user>", "Login to ArcOS (required for system access)"),
                ("help", "Show this help"),
                ("exit", "Exit ArcOS")
            ]
            
            status = "[red]Unauthenticated[/red]"
            access_level = "[yellow]Limited Access[/yellow]"
        
        commands_table = Table(show_header=True, header_style="bold magenta")
        commands_table.add_column("Command", style="cyan")
        commands_table.add_column("Description", style="white")
        
        for cmd, desc in commands_info:
            commands_table.add_row(cmd, desc)
        
        self.console.print(Panel(commands_table, title="ArcOS Commands", style="blue"))
        
        # Show system status
        status_panel = Panel(
            f"🔐 Authentication: {status}\n"
            f"📁 Filesystem access: {access_level}\n"
            f"🚀 Package management: {'[green]Enabled[/green]' if self.arcos.current_user else '[red]Disabled[/red]'}",
            title="System Status",
            style="green" if self.arcos.current_user else "yellow"
        )
        self.console.print(status_panel)
        
        return True
    
    def handle_exit(self, args) -> bool:
        """Handle exit command"""
        self.console.print("👋 Thank you for using ArcOS!", style="yellow")
        return False

class ArcOSShell:
    """ArcOS shell with authentication requirements"""
    
    def __init__(self, arcos_system):
        self.arcos = arcos_system
        self.console = arcos_system.console
        self.command_executor = ArcOSCommandExecutor(arcos_system)
        self._prompt = "arcos$ "
    
    def get_prompt(self) -> str:
        """Get the current prompt based on system state"""
        if self.arcos.current_user:
            user_info = self.arcos.users.get_user_info(self.arcos.current_user)
            if user_info and self.arcos.current_dir.startswith(user_info['home_dir']):
                display_dir = "~" + self.arcos.current_dir[len(user_info['home_dir']):]
            else:
                display_dir = self.arcos.current_dir
            
            return f"{self.arcos.current_user}@arcos:{display_dir}$ "
        else:
            return "arcos$ "
    
    def update_prompt(self):
        """Update prompt based on current state"""
        self._prompt = self.get_prompt()
    
    def run(self):
        """Main shell loop"""
        while True:
            try:
                command = input(self._prompt).strip()
                if not self.command_executor.execute_command(command):
                    break
            except KeyboardInterrupt:
                self.console.print("\n👋 Use 'exit' to quit ArcOS", style="yellow")
            except EOFError:
                self.console.print("\n👋 Goodbye!", style="yellow")
                break

class ArcOS:
    """Main ArcOS system with authentication requirements"""
    
    def __init__(self, data_dir: str = "~/.arcos"):
        self.data_dir = Path(data_dir).expanduser()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.security = ArcOSSecurity()
        self.filesystem = ArcOSFilesystem(self.data_dir)
        self.users = ArcOSUserManager(self.data_dir)
        self.packages = ArcOSPackageManager(self.filesystem)
        
        self.console = Console()
        self.current_user = None
        self.current_dir = "/"
        
        # Pass self to filesystem for authentication checks
        self.filesystem.arcos_system = self
        
        self.shell = ArcOSShell(self)

    def run(self):
        """Start ArcOS"""
        self.console.print(Panel(
            "[bold green]ArcOS Secure Environment v4.0[/bold green]\n"
            "[white]Authentication-Required Portable System[/white]\n"
            "[white]Real Package Management · Protected Filesystem[/white]",
            style="blue"
        ))
        
        # Check if users exist
        if not self.users.users:
            self.console.print("\n⚠️  No users configured. Run setup first:", style="yellow")
            self.console.print("  python arcos.py setup", style="cyan")
            return
        
        # Show authentication status
        if self.current_user:
            status_panel = Panel(
                f"🔐 Authentication: [green]Active[/green]\n"
                f"👤 User: [cyan]{self.current_user}[/cyan]\n"
                f"📁 Current directory: [blue]{self.current_dir}[/blue]\n"
                f"🚀 System access: [green]Enabled[/green]",
                title="System Status",
                style="green"
            )
        else:
            status_panel = Panel(
                f"🔐 Authentication: [red]Required[/red]\n"
                f"📁 Filesystem access: [red]Locked[/red]\n"
                f"🚀 Command execution: [yellow]Limited[/yellow]\n"
                f"💡 Use 'login <username>' to authenticate",
                title="System Status",
                style="yellow"
            )
        
        self.console.print(status_panel)
        self.console.print("")
        
        self.shell.run()

def setup_arcos():
    """Initial setup for ArcOS"""
    data_dir = Path("~/.arcos").expanduser()
    data_dir.mkdir(exist_ok=True)
    
    users_file = data_dir / "users.json"
    
    if users_file.exists():
        print("ArcOS is already set up!")
        return
    
    print("ArcOS v4.0 First Time Setup")
    print("============================")
    print("Secure Authentication-Required Environment")
    print("")
    
    users = {}
    
    # Set root password
    while True:
        password = getpass.getpass("Set root password: ")
        confirm = getpass.getpass("Confirm root password: ")
        if password == confirm:
            if len(password) >= 4:
                break
            else:
                print("Password must be at least 4 characters")
        else:
            print("Passwords don't match!")
    
    # Hash password
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    
    users['root'] = {
        "uid": 0,
        "password_hash": base64.b64encode(salt + key).decode(),
        "description": "System Administrator",
        "home_dir": "/root",
        "shell": "/bin/arcsh",
        "created": datetime.now().isoformat()
    }
    
    # Create regular user
    create_user = input("Create regular user? (y/n): ").lower().startswith('y')
    if create_user:
        username = input("Username: ")
        while True:
            password = getpass.getpass(f"Password for {username}: ")
            confirm = getpass.getpass(f"Confirm password for {username}: ")
            if password == confirm:
                if len(password) >= 4:
                    break
                else:
                    print("Password must be at least 4 characters")
            else:
                print("Passwords don't match!")
        
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        users[username] = {
            "uid": 1000,
            "password_hash": base64.b64encode(salt + key).decode(),
            "description": "Regular User",
            "home_dir": f"/home/{username}",
            "shell": "/bin/arcsh",
            "created": datetime.now().isoformat()
        }
    
    users_file.write_text(json.dumps(users, indent=2))
    
    # Initialize filesystem
    fs = ArcOSFilesystem(data_dir)
    print("✅ ArcOS v4.0 setup complete! Run 'python arcos.py' to start.")
    print("")
    print("Security Features:")
    print("  • Authentication required for system access")
    print("  • Protected filesystem")
    print("  • Real package management")
    print("  • Secure command execution")

def main():
    """Main entry point"""
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        setup_arcos()
    else:
        arcos = ArcOS()
        arcos.run()

if __name__ == "__main__":
    main()