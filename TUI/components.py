from .globals import *

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

class FileSelectScreen(ModalScreen):
    
    CSS_PATH = "../layout/file_select_screen.tcss"
    BINDINGS = [
        ("escape", "dismiss", "Cancel"),
    ]
    
    def compose(self) -> ComposeResult:
        with Container(classes="file-select-container"):
            yield Label("Select a firmware file to disassemble:", classes="file-select-message")
            yield DirectoryTree(path=".", classes="file-tree")
    
    def on_mount(self) -> None:
        container = self.query_one(".file-select-container")
        container.border_title = "Select Firmware File"
    
    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        """Handle file selection"""
        if os.path.isfile(event.path):
            self.app.disassemble_file(str(event.path))
            self.dismiss()
