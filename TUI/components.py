from .globals import *
from pathlib import Path
from typing import Iterable
from rich.markdown import Markdown
from rich.console import Console

class DisasmTextAreaTheme(TextAreaTheme):
    def __init__(self):
        super().__init__(name="disasm")

    DEFAULT = Color.parse("#E0E0E0")
    COMMENT = galaxy_secondary
    INSTRUCTION = galaxy_primary
    NUMBER = galaxy_warning
    REGISTER = galaxy_accent
    PUNCTUATION = Color.parse("#808080")
    OPERATOR = galaxy_success
    BACKGROUND = galaxy_panel
    SELECTION_BACKGROUND = Color.parse("#404080")
    CURSOR = galaxy_primary
    CURSOR_LINE = Color.parse("#2A2A4A")
    LINE_NUMBER = Color.parse("#606080")
    LINE_NUMBER_BACKGROUND = galaxy_background

    def syntax_highlights(self, text: str) -> Syntax:
        highlights = []
        for line in text.split("\n"):
            if ";" in line:
                code, comment = line.split(";", 1)
                highlights.append((code, "default"))
                highlights.append((f";{comment}", "comment"))
            elif line.strip().startswith("0x"):
                addr_end = line.find(":")
                if addr_end != -1:
                    highlights.append((line[:addr_end], "number"))
                    highlights.append((":", "punctuation"))
                    highlights.append((line[addr_end+1:], "instruction"))
            else:
                highlights.append((line, "default"))
        
        return highlights

class ToggleableDirectoryTree(DirectoryTree):
    
    BINDINGS = [
        Binding("h", "toggle_hidden", "Toggle Hidden", show=True),
    ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.show_hidden = False
    
    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        if self.show_hidden:
            return paths
        else:
            return [path for path in paths if not path.name.startswith(".")]
    
    def action_toggle_hidden(self):
        self.show_hidden = not self.show_hidden
        self.reload()

class FileSelectScreen(ModalScreen):
    
    CSS_PATH = "../layout/file_select_screen.tcss"
    BINDINGS = [
        ("escape", "dismiss", "Cancel"),
    ]
    
    def compose(self) -> ComposeResult:
        with Container(classes="file-select-container"):
            yield Label("Press 'h' to toggle hidden directories\nSelect a firmware file to disassemble:", classes="file-select-message")
            yield ToggleableDirectoryTree(path=Path.home(), classes="file-tree")
    
    def on_mount(self):
        container = self.query_one(".file-select-container")
        container.border_title = "Select Firmware File"
    
    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        """Handle file selection"""
        if os.path.isfile(event.path):
            self.app.disassemble_file(str(event.path))
            self.dismiss()

class HelpScreen(ModalScreen):
    """Help screen showing keybinds and app introduction"""
    CSS_PATH = "../layout/help_screen.tcss"
    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("q", "dismiss", "Close"),
    ]
    def on_mount(self):
        container = self.query_one(".help-modal-container")
        container.border_title = "Help - ESPionage v1.0.0"
    
    def compose(self) -> ComposeResult:
        help_content = """# ESPionage v1.0.0

ESPionage is a comprehensive firmware analysis tool designed for ESP8266/ESP32 devices. It provides powerful capabilities for reverse engineering, disassembly, and analysis of firmware images.

- **Disassembly**: Full disassembly of ESP8266/ESP32 firmware
- **Hex Viewer**: Raw hexadecimal view of firmware data  
- **Parser Tools**: Extract headers, partition tables, jump tables, strings, URLs, and files
- **Memory Operations**: Read firmware from devices and flash new firmware
- **Real-time Analysis**: Multi-threaded processing for efficient analysis

| Keybind | Action | Description |
|---------|--------|-------------|
| `Ctrl+Q` | Quit | Exit the application |
| `Ctrl+O` | Open File | Load firmware file for analysis |
| `Ctrl+D` | Focus Disassembler | Switch focus to disassembly view |
| `Ctrl+H` | Focus Hex Viewer | Switch focus to hex viewer |
| `Ctrl+R` | Focus Reader | Switch to firmware reader tab |
| `Ctrl+F` | Focus Flasher | Switch to firmware flasher tab |
| `?` | Help | Show this help screen |
| `Escape` | Close Modal | Close current modal/dialog |


| Context | Key | Action |
|---------|-----|--------|
| File Browser | `h` | Toggle hidden files/directories |
| File Browser | `Enter` | Select file |
| Help Screen | `q` | Close help |

---

*For more information and updates, visit the project repository.*"""
        
        with Container(classes="help-modal-container"):
            with Container(classes="help-content-wrapper"):
                yield Label("ESPionage Help", classes="help-title")
                with ScrollableContainer(classes="help-scroll"):
                    yield Static(Markdown(help_content), classes="help-text", markup=True)