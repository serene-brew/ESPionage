from .components import *
from .utils import *
from .espionage import *

class baseplate(App):
    CSS_PATH = ["../layout/style.tcss", "../layout/disasm_textarea.tcss"]
    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+o", "show_file_select_screen", "Open Firmware"),
        ("ctrl+d", "focus_disassembler", "Focus Disassembler"),
    ]
     
    def on_mount(self) -> None:
        self.register_theme(GALAXY_THEME)
        self.theme = "galaxy"

        self.focused_index = 0
        self.focusable_containers = ["left-panel", "right-top", "right-bottom"]
        left_panel = self.query_one(".left-panel")

        empty_message = Static(
            "No firmware loaded\n\n" +
            "Press Ctrl+O to load a firmware file\n" +
            "for disassembly & analysis\n\n"+
            "ESPionage v1.0.0\n"+
            "by Serene-Brew ",
            classes="empty-state"
        )
        left_panel.mount(empty_message)

        custom_theme = DisasmTextAreaTheme()
    def action_quit(self) -> None:
        os.system('reset')
        os._exit(0)
        
    def action_focus_disassembler(self) -> None:
        try:
            disasm_display = self.query_one(".disasm-display", RichLog)
            disasm_display.focus()
        except:
            self.notify("No firmware loaded", severity="warning")

    def action_show_file_select_screen(self) -> None:
        self.push_screen(FileSelectScreen())
    def on_radio_button_changed(self, event: RadioButton.Changed) -> None:
        if not event.radio_button.id or not event.radio_button.id.startswith("baud-"):
            return

        if event.radio_button.value:
            baud_ids = ["baud-9600", "baud-74880", "baud-115200", "baud-921600"]

            for button_id in baud_ids:
                if button_id != event.radio_button.id:
                    try:
                        button = self.query_one(f"#{button_id}", RadioButton)
                        button.value = False
                    except:
                        pass


    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "dump-button":
            self.handle_dump_flash()
    def compose(self) -> ComposeResult:
        yield Header()

        with Container(classes="main-container"):
            with Horizontal(classes="content-horizontal"):

                left_panel = Container(classes="left-panel")
                left_panel.border_title = "Disassembler"

                yield left_panel
                
                with Vertical(classes="right-container"):
                    right_top = Container(classes="right-top")
                    right_top.border_title = "Parser"
                    
                    with right_top:
                        with TabbedContent():
                            with TabPane("Header", id="tab-header"):
                                yield Static("Header contents")
                            
                            with TabPane("Partition-Table", id="tab-partition-table"):
                                yield Static("partition table contents")
                            
                            with TabPane("Export-table", id="tab-export-table"):
                                yield Static("export table contents")
                            with TabPane("Functions", id="tab-function-table"):
                                yield Static("function table contents")
                            with TabPane("Call-Signatures", id="tab-call-signatures"):
                                yield Static("function call signatures") 
                            with TabPane("Strings", id="tab-strings"):
                                yield Static("extracted strings from firmware") 
                    yield right_top
                        
                    right_bottom = Container(classes="right-bottom")
                    right_bottom.border_title = "Memory"
                                        
                    with right_bottom:
                        with TabbedContent():
                            with TabPane("Dumper", id="tab-dumper"):
                                #yield Static("Flash memory dumper")
                                with Vertical(classes="dumper-vertical"):
                                    with Vertical(classes="port-baud-horizontal"):
                                        with Horizontal(classes="port-group"):
                                            yield Label("Port: ")
                                            yield Input(placeholder=" e.g COM1 or /dev/ttyUSB0", id="port-input", compact=True)
                                        
                                        with Horizontal(classes="baud-group"):
                                            yield Label("Baud Rate:", id="baudrate-label")

                                            with Horizontal(classes="baud-radios"):
                                                yield RadioButton("9600 ", id="baud-9600", compact=True)
                                                yield RadioButton("74880 ", id="baud-74880", compact=True)
                                                yield RadioButton("115200 ", id="baud-115200", compact=True) 
                                                yield RadioButton("921600 ", id="baud-921600", compact=True)
                                                
                                            
                                    
                                    with Horizontal(classes="addresses-horizontal"):
                                        yield Label("Extraction addresses: ", classes="addresses-label")
                                        yield Input(placeholder=" e.g 0x00000000", id="start-address-input", classes="address-input", compact=True)
                                        yield Static("to", classes="to-label")
                                        yield Input(placeholder=" e.g 0x00400000", id="end-address-input", classes="address-input", compact=True)
                                    with Horizontal(classes="firmware-name"):
                                        yield Label("Firmware Name: ")
                                        yield Input(placeholder=" /path/to/firmware.bin", id="name-input", compact=True)
                                    with Horizontal(classes="dump-button-container"):
                                        yield Button("Dump Flash", id="dump-button", variant="success", compact=True)
                                    
                                    yield TextArea(
                                        text="Ready for memory dump...",
                                        read_only=True,
                                        show_line_numbers=False,
                                        disabled=True,
                                        id="dumper-output",
                                        classes="dumper-textarea"
                                    )
                            with TabPane("Flasher", id="tab-flasher"):
                                yield Static("ROM flasher")
                            
                            with TabPane("Hex-Viewer", id="tab-hex-viewer"):
                                yield Static("hex editor contents")
                    yield right_bottom
        
        yield Footer()

    def disassemble_file(self, file_path: str) -> None:

        self.notify("Analyzing Firmware. This may take some time", severity="information")

        thread = threading.Thread(target=self._disassemble_worker, args=(file_path,))
        thread.daemon = True
        thread.start()
    
    def _disassemble_worker(self, file_path: str) -> None:
        try:
            disasm_result = disassemble_esp8266_full(str(file_path))
            self.call_from_thread(self._update_disassembly_display, disasm_result, file_path)
            
        except Exception as e:
            self.call_from_thread(self.notify, f"Error disassembling file: {str(e)}", "error")
    
    def _update_disassembly_display(self, disasm_result: str, file_path: str) -> None:
        try:
            left_panel = self.query_one(".left-panel")
            left_panel.border_subtitle = os.path.basename(file_path)

            for child in left_panel.children:
                child.remove()
            disasm_display = RichLog(
                classes="disasm-display", 
                highlight=True, 
                markup=True,
                auto_scroll=False
            )

            highlighted_text = self.create_highlighted_disasm(disasm_result)
            disasm_display.write(highlighted_text)

            left_panel.mount(disasm_display)
            
            self.notify("Firmware analysis complete!", severity="information")
            disasm_display.focus()

        except Exception as e:
            self.notify(f"Error updating display: {str(e)}", severity="error")