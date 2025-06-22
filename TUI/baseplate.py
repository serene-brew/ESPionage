from .components import *
from .utils import *
from .espionage import *
from ROM_rw.hex_viewer import hex_viewer # imported it here
from parser.jump_table import *
from parser.headers import parse_esp32_header
from parser.partition_table import parse_esp32_partition_table
from parser.strings import extract_strings_from_firmware
from parser.urls import extract_urls_from_firmware
from parser.files import extract_files_from_firmware
from textual.containers import ScrollableContainer

from rich.console import Console
from rich.text import Text
from io import StringIO

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
            "Press Ctrl+R/Ctrl+F to focus\n" +
            "firmware reader/flasher and extract firmware\n"+
            "out of memory or write into memory\n\n",
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
                                yield Static(
                                    "No firmware loaded\n\n" +
                                    "Press Ctrl+O to load a firmware file\n" +
                                    "for disassembly & analysis\n\n"+
                                    "ESPionage v1.0.0\n"+
                                    "by Serene-Brew ",
                                    classes="empty-state"
                                )
                            with TabPane("Partition-Table", id="tab-partition-table"):
                                yield Static(
                                    "No firmware loaded\n\n" +
                                    "Press Ctrl+O to load a firmware file\n" +
                                    "for disassembly & analysis\n\n"+
                                    "ESPionage v1.0.0\n"+
                                    "by Serene-Brew ",
                                    classes="empty-state"
                                )
                            with TabPane("Jump-Table", id="tab-jump-table"):
                                yield Static(
                                    "No firmware loaded\n\n" +
                                    "Press Ctrl+O to load a firmware file\n" +
                                    "for disassembly & analysis\n\n"+
                                    "ESPionage v1.0.0\n"+
                                    "by Serene-Brew ",
                                    classes="empty-state"
                                )
                            with TabPane("Functions", id="tab-function-table"):
                                yield Static(
                                    "No firmware loaded\n\n" +
                                    "Press Ctrl+O to load a firmware file\n" +
                                    "for disassembly & analysis\n\n"+
                                    "ESPionage v1.0.0\n"+
                                    "by Serene-Brew ",
                                    classes="empty-state"
                                )
                            with TabPane("Call-Signatures", id="tab-call-signatures"):
                                yield Static(
                                    "No firmware loaded\n\n" +
                                    "Press Ctrl+O to load a firmware file\n" +
                                    "for disassembly & analysis\n\n"+
                                    "ESPionage v1.0.0\n"+
                                    "by Serene-Brew ",
                                    classes="empty-state"
                                )
                            with TabPane("Strings", id="tab-strings"):
                                yield Static(
                                    "No firmware loaded\n\n" +
                                    "Press Ctrl+O to load a firmware file\n" +
                                    "for disassembly & analysis\n\n"+
                                    "ESPionage v1.0.0\n"+
                                    "by Serene-Brew ",
                                    classes="empty-state"
                                ) 
                            with TabPane("URLs", id="tab-urls"):
                                yield Static(
                                    "No firmware loaded\n\n" +
                                    "Press Ctrl+O to load a firmware file\n" +
                                    "for disassembly & analysis\n\n"+
                                    "ESPionage v1.0.0\n"+
                                    "by Serene-Brew ",
                                    classes="empty-state"
                                )
                            with TabPane("Files", id="tab-files"):
                                yield Static(
                                    "No firmware loaded\n\n" +
                                    "Press Ctrl+O to load a firmware file\n" +
                                    "for disassembly & analysis\n\n"+
                                    "ESPionage v1.0.0\n"+
                                    "by Serene-Brew ",
                                    classes="empty-state"
                                )
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
                                        read_only=False,
                                        show_line_numbers=True,
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
                                        show_line_numbers=True,
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

############################################THREAD WORKERS############################################
    def _hex_view_worker(self, file_path: str) -> None:
        try:
            hex_output = hex_viewer(file_path)
            self.call_from_thread(self._update_hex_viewer_display, hex_output)
        except Exception as e:
            self.call_from_thread(self.notify, f"Error generating hex view: {str(e)}", "error")
    def _disassemble_worker(self, file_path: str) -> None:
        try:
            disasm_result = disassemble_esp8266_full(str(file_path))
            self.call_from_thread(self._update_disassembly_display, disasm_result, file_path)
            
        except Exception as e:
            self.call_from_thread(self.notify, f"Error disassembling file: {str(e)}", "error")
    def _jump_table_worker(self, file_path: str) -> None:
        try:
            jump_table_output, status = ShowJumpTables(file_path)
            self.call_from_thread(self._update_jump_table_display, jump_table_output, status)
        except Exception as e:
            self.call_from_thread(self.notify, f"Error analyzing jump tables: {str(e)}", "error")

    def _header_worker(self, file_path: str) -> None:
        try:
            header_output, status = parse_esp32_header(file_path)
            self.call_from_thread(self._update_header_display, header_output, status)
        except Exception as e:
            self.call_from_thread(self.notify, f"Error parsing headers: {str(e)}", "error")

    def _partition_worker(self, file_path: str) -> None:
        try:
            partition_output, status = parse_esp32_partition_table(file_path)
            self.call_from_thread(self._update_partition_display, partition_output, status)
        except Exception as e:
            self.call_from_thread(self.notify, f"Error parsing partition table: {str(e)}", "error")

    def _strings_worker(self, file_path: str) -> None:
        try:
            strings_output, status = extract_strings_from_firmware(file_path)
            self.call_from_thread(self._update_strings_display, strings_output, status)
        except Exception as e:
            self.call_from_thread(self.notify, f"Error extracting strings: {str(e)}", "error")

    def _urls_worker(self, file_path: str) -> None:
        try:
            urls_output, status = extract_urls_from_firmware(file_path)
            self.call_from_thread(self._update_urls_display, urls_output, status)
        except Exception as e:
            self.call_from_thread(self.notify, f"Error extracting URLs: {str(e)}", "error")

    def _files_worker(self, file_path: str) -> None:
        try:
            files_output, status = extract_files_from_firmware(file_path)
            self.call_from_thread(self._update_files_display, files_output, status)
        except Exception as e:
            self.call_from_thread(self.notify, f"Error extracting files: {str(e)}", "error")
#######################################################################################################
############################################THREAD UPDATERS############################################
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
            
            # Apply syntax highlighting to hex output
            highlighted_hex = self.create_highlighted_hex(hex_output)
            hex_display.write(highlighted_hex)
            hex_tab.mount(hex_display)
            
        except Exception as e:
            self.notify(f"Error updating hex viewer display: {str(e)}", severity="error")
    
    def _update_jump_table_display(self, jump_table_output: str, status: int) -> None:
        try:
            jump_table_tab = self.query_one("#tab-jump-table")
            jump_table_tab.remove_children()
    
            if not status:
                jump_table_tab.mount(Static("No jump tables found in firmware", classes="empty-state"))
                return
            
            rich_text = Text.from_ansi(jump_table_output)
    
            scroll_container = ScrollableContainer()
            jump_table_tab.mount(scroll_container)
    
            static_content = Static(
                rich_text,
                expand=False,
                markup=True,
                classes="jump-table-content"
            )
            scroll_container.mount(static_content)
    
        except Exception as e:
            self.notify(f"Error updating jump table display: {str(e)}", severity="error")

    def _update_header_display(self, header_output: str, status: int) -> None:
        try:
            header_tab = self.query_one("#tab-header")
            header_tab.remove_children()

            if not status:
                header_tab.mount(Static("No header found in firmware", classes="empty-state"))
                return

            scroll_container = ScrollableContainer()
            header_tab.mount(scroll_container)

            static_content = Static(header_output, expand=True, markup=False)
            scroll_container.mount(static_content)

        except Exception as e:
            self.notify(f"Error updating header display: {str(e)}", severity="error")

    def _update_partition_display(self, partition_output: str, status: int) -> None:
        try:
            partition_tab = self.query_one("#tab-partition-table")
            partition_tab.remove_children()
            if not status:
                partition_tab.mount(Static("No valid partition table found in firmware", classes="empty-state"))
                return

            scroll_container = ScrollableContainer()
            partition_tab.mount(scroll_container)

            static_content = Static(partition_output, expand=True, markup=False)
            scroll_container.mount(static_content)

        except Exception as e:
            self.notify(f"Error updating partition display: {str(e)}", severity="error")

    def _update_strings_display(self, strings_output: str, status: int) -> None:
        try:
            strings_tab = self.query_one("#tab-strings")
            strings_tab.remove_children()
            if not status:
                strings_tab.mount(Static("No valid string table found in firmware", classes="empty-state"))
                return
            scroll_container = ScrollableContainer()
            strings_tab.mount(scroll_container)

            static_content = Static(strings_output, expand=True, markup=False)
            scroll_container.mount(static_content)

        except Exception as e:
            self.notify(f"Error updating strings display: {str(e)}", severity="error")

    def _update_urls_display(self, urls_output: str, status: int) -> None:
        try:
            urls_tab = self.query_one("#tab-urls")
            urls_tab.remove_children()
            if not status:
                urls_tab.mount(Static("No valid URLs extracted from string table", classes="empty-state"))
                return
            scroll_container = ScrollableContainer()
            urls_tab.mount(scroll_container)

            static_content = Static(urls_output, expand=True, markup=False)
            scroll_container.mount(static_content)

        except Exception as e:
            self.notify(f"Error updating URLs display: {str(e)}", severity="error")

    def _update_files_display(self, files_output: str, status: int) -> None:
        try:
            files_tab = self.query_one("#tab-files")
            files_tab.remove_children()
            if not status:
                files_tab.mount(Static("No files were found in firmware", classes="empty-state"))
                return
            scroll_container = ScrollableContainer()
            files_tab.mount(scroll_container)

            static_content = Static(files_output, expand=True, markup=False)
            scroll_container.mount(static_content)

        except Exception as e:
            self.notify(f"Error updating files display: {str(e)}", severity="error")
#######################################################################################################
    def disassemble_file(self, file_path: str) -> None:
        self.current_firmware_path = file_path
        self.notify("Analyzing Firmware. This may take some time", severity="information")

        # Start disassembly, hex viewing, jump table analysis, and header parsing
        disasm_thread = threading.Thread(target=self._disassemble_worker, args=(file_path,))
        disasm_thread.daemon = True
        disasm_thread.start()
        
        hex_thread = threading.Thread(target=self._hex_view_worker, args=(file_path,))
        hex_thread.daemon = True
        hex_thread.start()

        jump_table_thread = threading.Thread(target=self._jump_table_worker, args=(file_path,))
        jump_table_thread.daemon = True
        jump_table_thread.start()

        header_thread = threading.Thread(target=self._header_worker, args=(file_path,))
        header_thread.daemon = True
        header_thread.start()

        partition_thread = threading.Thread(target=self._partition_worker, args=(file_path,))
        partition_thread.daemon = True
        partition_thread.start()

        strings_thread = threading.Thread(target=self._strings_worker, args=(file_path,))
        strings_thread.daemon = True
        strings_thread.start()

        urls_thread = threading.Thread(target=self._urls_worker, args=(file_path,))
        urls_thread.daemon = True
        urls_thread.start()

        files_thread = threading.Thread(target=self._files_worker, args=(file_path,))
        files_thread.daemon = True
        files_thread.start()