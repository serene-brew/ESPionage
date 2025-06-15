from .components import *
from .utils import *
from .espionage import *
from ROM_rw.hex_viewer import hex_viewer # imported it here

class baseplate(App):
    CSS_PATH = ["../layout/style.tcss", "../layout/disasm_textarea.tcss"]
    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+o", "show_file_select_screen", "Open Firmware"),
        ("ctrl+d", "focus_disassembler", "Focus Disassembler"),
        ("ctrl+h", "focus_hex_viewer", "Focus Hex Viewer"),
        ("ctrl+r", "focus_reader", "Focus Reader"),
        ("ctrl+f", "focus_flasher", "Focus Flasher"),
    ]
     
    def on_mount(self) -> None:
        self.register_theme(GALAXY_THEME)
        self.theme = "galaxy"

        self.focused_index = 0
        self.focusable_containers = ["left-panel", "right-top", "right-bottom"]
        self.current_firmware_path = None  # Added this to track currently loaded firmware
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
    def action_focus_hex_viewer(self) -> None:
        try:
            hex_display = self.query_one(".hex-display", RichLog)
            hex_display.focus()
        except:
            self.notify("No firmware loaded", severity="warning")
    
    def action_focus_reader(self) -> None:
        try:
            tabbed_content = self.query_one(".right-bottom TabbedContent")
            tabbed_content.active = "tab-dumper"

            port_input = self.query_one("#port-input", Input)
            port_input.focus()

        except Exception as e:
            self.notify("Could not focus Dumper port input", severity="warning")

    def action_focus_flasher(self) -> None:
        try:
            tabbed_content = self.query_one(".right-bottom TabbedContent")
            tabbed_content.active = "tab-flasher"

            port_input_flasher = self.query_one("#port-input-flasher", Input)
            port_input_flasher.focus()
        except Exception as e:
            self.notify("Could not focus Flasher port input", severity="warning")
    

    def action_show_file_select_screen(self) -> None:
        self.push_screen(FileSelectScreen())

    def on_radio_button_changed(self, event: RadioButton.Changed) -> None:    

        if event.radio_button.id and event.radio_button.id.startswith("baud-"):
            if event.radio_button.value:
                baud_ids = ["baud-9600", "baud-74880", "baud-115200", "baud-921600"]
                for button_id in baud_ids:
                    if button_id != event.radio_button.id:
                        try:
                            button = self.query_one(f"#{button_id}", RadioButton)
                            button.value = False
                        except:
                            pass

        elif event.radio_button.id and event.radio_button.id.startswith("flasher-baud-"):
            if event.radio_button.value:
                flasher_baud_ids = ["flasher-baud-115200", "flasher-baud-460800", "flasher-baud-921600"]
                for button_id in flasher_baud_ids:
                    if button_id != event.radio_button.id:
                        try:
                            button = self.query_one(f"#{button_id}", RadioButton)
                            button.value = False
                        except:
                            pass

        elif event.radio_button.id in ["not-erase-eeprom-flasher", "erase-eeprom-flasher"]:
            if event.radio_button.value:
                eeprom_ids = ["not-erase-eeprom-flasher", "erase-eeprom-flasher"]
                for button_id in eeprom_ids:
                    if button_id != event.radio_button.id:
                        try:
                            button = self.query_one(f"#{button_id}", RadioButton)
                            button.value = False
                        except:
                            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "dump-button":
            self.handle_dump_flash()
        elif event.button.id == "flash-button":
            self.handle_flash_firmware()

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
                            with TabPane("Reader", id="tab-dumper"):
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
                                        yield Button("Read Firmware", id="dump-button", variant="success", compact=True)
                                    
                                    yield TextArea(
                                        text="Ready for memory dump...",
                                        read_only=True,
                                        show_line_numbers=False,
                                        disabled=True,
                                        id="dumper-output",
                                        classes="dumper-textarea"
                                    )
                            with TabPane("Flasher", id="tab-flasher"):
                                # yield Static("ROM flasher")
                                with Vertical(classes="flasher-vertical"):
                                    with Vertical(classes="port-baud-flasher-horizontal"):
                                        with Horizontal(classes="port-flasher-group"):
                                            yield Label("Port: ")
                                            yield Input(placeholder=" e.g COM1 or /dev/ttyUSB0", id="port-input-flasher", compact=True)
                                        
                                        with Horizontal(classes="baud-flasher-group"):
                                            yield Label("Baud Rate:", id="baudrate-flasher-label")

                                            with Horizontal(classes="baud-flasher-radios"):
                                                yield RadioButton("115200 ", id="flasher-baud-115200", compact=True)
                                                yield RadioButton("460800 ", id="flasher-baud-460800", compact=True)
                                                yield RadioButton("921600 ", id="flasher-baud-921600", compact=True)                                            
                                    
                                    with Horizontal(classes="addresses-flasher-horizontal"):
                                        yield Label("Flash Offset: ", classes="flash-addresses-label")
                                        yield Input(placeholder=" e.g 0x00000000", id="flash-address-input", classes="address-input", compact=True)
                                        yield Label("  Erase EEPROM:", id="erase-eeprom-flasher-label")
                                        with Horizontal(classes="eeprom-flasher-radios"):
                                            yield RadioButton("No ", id="not-erase-eeprom-flasher", compact=True)
                                            yield RadioButton("Yes ", id="erase-eeprom-flasher", compact=True)
                                    with Horizontal(classes="flasher-firmware-name"):
                                        yield Label("Firmware path: ")
                                        yield Input(placeholder=" /path/to/firmware.bin", id="name-input-flasher", compact=True)
                                    with Horizontal(classes="flash-button-container"):
                                        yield Button("Flash Firmware", id="flash-button", variant="success", compact=True)
                                    
                                    yield TextArea(
                                        text="Ready for memory flashing...",
                                        read_only=True,
                                        show_line_numbers=False,
                                        disabled=True,
                                        id="flasher-output",
                                        classes="flasher-textarea"
                                    )
                            
                            with TabPane("Hex-Viewer", id="tab-hex-viewer"):
                                yield Static("No firmware loaded", classes="empty-state")
                    yield right_bottom
        yield Footer()     
    def handle_hex_view(self) -> None:
        pass
    
    def _hex_view_worker(self, file_path: str) -> None:
        try:
            hex_output = hex_viewer(file_path)
            self.call_from_thread(self._update_hex_viewer_display, hex_output)
        except Exception as e:
            self.call_from_thread(self.notify, f"Error generating hex view: {str(e)}", "error")
    
    def _update_hex_viewer_display(self, hex_output: str) -> None:
        try:
            hex_tab = self.query_one("#tab-hex-viewer")
            
            for child in hex_tab.children:
                child.remove()
            
            hex_display = RichLog(
                classes="hex-display", 
                highlight=False, 
                markup=False,
                auto_scroll=False
            )
            
            hex_display.write(hex_output)
            hex_tab.mount(hex_display)
            
        except Exception as e:
            self.notify(f"Error updating hex viewer display: {str(e)}", severity="error")

    def disassemble_file(self, file_path: str) -> None:
        self.current_firmware_path = file_path  # Storing the firmware path
        self.notify("Analyzing Firmware. This may take some time", severity="information")

        # Start both disassembly and hex viewing
        disasm_thread = threading.Thread(target=self._disassemble_worker, args=(file_path,))
        disasm_thread.daemon = True
        disasm_thread.start()
        
        hex_thread = threading.Thread(target=self._hex_view_worker, args=(file_path,))
        hex_thread.daemon = True
        hex_thread.start()
    
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