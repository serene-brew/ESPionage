from .globals import *
from .baseplate import baseplate
from .syntax import SyntaxHighlight
from .utils import *

class ESPionage(SyntaxHighlight):
    def _update_dump_output(self, text):
        try:
            output_area = self.query_one("#dumper-output", TextArea)
            output_area.text = text

            lines = text.split('\n')
            last_line = max(0, len(lines) - 1)
            last_column = len(lines[-1]) if lines else 0
            output_area.cursor_location = (last_line, last_column)

        except Exception as e:
            pass
    
    def _dump_flash_worker(self, port, baud_rate, start_address, end_address, firmware_name):

        output_queue = queue.Queue()
        monitor_running = threading.Event()
        monitor_running.set()

        class QueueCapture:
            def __init__(self, queue_obj):
                self.queue = queue_obj
                self.current_line = ""
                self.is_progress_line = False

            def write(self, text):
                if not text:
                    return

                if '\r' in text:
                    parts = text.split('\r')

                    for i, part in enumerate(parts):
                        if i == 0:
                            self.current_line += part
                        else:
                            if part.strip():
                                self.queue.put(('replace_line', part.strip()))
                                self.current_line = ""
                                self.is_progress_line = True
                else:
                    if text == '\n':
                        if self.current_line.strip() or not self.is_progress_line:
                            self.queue.put(('add_line', self.current_line))
                        self.current_line = ""
                        self.is_progress_line = False
                    else:
                        self.current_line += text
                        if '\n' in text:
                            lines = (self.current_line).split('\n')
                            for line in lines[:-1]:
                                if line.strip() or not self.is_progress_line:
                                    self.queue.put(('add_line', line))
                            self.current_line = lines[-1]
                            self.is_progress_line = False

            def flush(self):
                if self.current_line.strip():
                    self.queue.put(('add_line', self.current_line))
                    self.current_line = ""
                    self.is_progress_line = False
        def monitor_output():
            lines = ["Starting flash dump..."]

            while monitor_running.is_set():
                try:
                    action, text = output_queue.get(timeout=0.1)

                    if action == 'add_line':
                        lines.append(text)
                    elif action == 'replace_line':
                        if lines:
                            lines[-1] = text
                        else:
                            lines.append(text)

                    formatted_text = '\n'.join(lines)
                    self.call_from_thread(self._update_dump_output, formatted_text)

                except queue.Empty:
                    continue
                except Exception:
                    break
        monitor_thread = threading.Thread(target=monitor_output, daemon=True)
        monitor_thread.start()

        old_stdout = sys.stdout
        queue_capture = QueueCapture(output_queue)
        sys.stdout = queue_capture

        try:
            read_esp_flash(port, baud_rate, start_address, end_address, firmware_name)

            queue_capture.flush()

            output_queue.put(('add_line', "Flash dump completed successfully!"))
            time.sleep(0.5)
            self.call_from_thread(self.notify, "Flash dump completed!", severity="information")

        except Exception as e:
            error_msg = f"ERROR: Flash dump failed: {str(e)}"
            output_queue.put(('add_line', error_msg))
            self.call_from_thread(self.notify, f"Flash dump failed: {str(e)}", severity="error")

        finally:
            monitor_running.clear()
            sys.stdout = old_stdout
            time.sleep(0.1)
    def handle_dump_flash(self) -> None:
        try:
            port = self.query_one("#port-input", Input).value.strip()
            start_addr = self.query_one("#start-address-input", Input).value.strip()
            end_addr = self.query_one("#end-address-input", Input).value.strip()
            firmware_name = self.query_one("#name-input", Input).value.strip()

            baud_rate = None
            baud_buttons = ["baud-9600", "baud-74880", "baud-115200", "baud-921600"]
            baud_values = [9600, 74880, 115200, 921600]

            for i, button_id in enumerate(baud_buttons):
                try:
                    button = self.query_one(f"#{button_id}", RadioButton)
                    if button.value:
                        baud_rate = baud_values[i]
                        break
                except:
                    pass
                
            if not port:
                self.notify("Please enter a port name", severity="error")
                return
            if not baud_rate:
                self.notify("Please select a baud rate", severity="error")
                return
            if not start_addr:
                self.notify("Please enter start address", severity="error")
                return
            if not end_addr:
                self.notify("Please enter end address", severity="error")
                return
            if not firmware_name:
                self.notify("Please enter firmware name", severity="error")
                return

            try:
                start_address = int(start_addr, 16) if start_addr.startswith('0x') else int(start_addr)
                end_address = int(end_addr, 16) if end_addr.startswith('0x') else int(end_addr)
            except ValueError:
                self.notify("Invalid address format", severity="error")
                return

            output_area = self.query_one("#dumper-output", TextArea)
            output_area.text = "Starting flash dump...\n"

            thread = threading.Thread(
                target=self._dump_flash_worker, 
                args=(port, baud_rate, start_address, end_address, firmware_name)
            )
            thread.daemon = True
            thread.start()

        except Exception as e:
            self.notify(f"Error: {str(e)}", severity="error")

    def _update_flash_output(self, text):
        try:
            output_area = self.query_one("#flasher-output", TextArea)
            output_area.text = text

            lines = text.split('\n')
            last_line = max(0, len(lines) - 1)
            last_column = len(lines[-1]) if lines else 0
            output_area.cursor_location = (last_line, last_column)

        except Exception as e:
            pass

    def _flash_firmware_worker(self, port, baud_rate, flash_offset, firmware_path, erase_eeprom):
        output_queue = queue.Queue()
        monitor_running = threading.Event()
        monitor_running.set()

        class QueueCapture:
            def __init__(self, queue_obj):
                self.queue = queue_obj
                self.current_line = ""
                self.is_progress_line = False

            def write(self, text):
                if not text:
                    return

                if '\r' in text:
                    parts = text.split('\r')
                    for i, part in enumerate(parts):
                        if i == 0:
                            self.current_line += part
                        else:
                            if part.strip():
                                self.queue.put(('replace_line', part.strip()))
                                self.current_line = ""
                                self.is_progress_line = True
                else:
                    if text == '\n':
                        if self.current_line.strip() or not self.is_progress_line:
                            self.queue.put(('add_line', self.current_line))
                        self.current_line = ""
                        self.is_progress_line = False
                    else:
                        self.current_line += text
                        if '\n' in text:
                            lines = (self.current_line).split('\n')
                            for line in lines[:-1]:
                                if line.strip() or not self.is_progress_line:
                                    self.queue.put(('add_line', line))
                            self.current_line = lines[-1]
                            self.is_progress_line = False
                

            def flush(self):
                if self.current_line.strip():
                    self.queue.put(('add_line', self.current_line))
                    self.current_line = ""
                    self.is_progress_line = False
        

        def monitor_output():
            lines = ["Starting firmware flash..."]

            while monitor_running.is_set():
                try:
                    action, text = output_queue.get(timeout=0.1)

                    if action == 'add_line':
                        lines.append(text)
                    elif action == 'replace_line':
                        if lines:
                            lines[-1] = text
                        else:
                            lines.append(text)

                    formatted_text = '\n'.join(lines)
                    self.call_from_thread(self._update_flash_output, formatted_text)

                except queue.Empty:
                    continue
                except Exception:
                    break

        monitor_thread = threading.Thread(target=monitor_output, daemon=True)
        monitor_thread.start()

        old_stdout = sys.stdout
        queue_capture = QueueCapture(output_queue)
        sys.stdout = queue_capture

        try:
            # You'll need to implement this function in your code
            write_esp_flash(port, baud_rate, flash_offset, firmware_path, erase_eeprom)

            queue_capture.flush()
            output_queue.put(('add_line', "Firmware flash completed successfully!"))
            time.sleep(0.5)
            self.call_from_thread(self.notify, "Firmware flash completed!", severity="information")

        except Exception as e:
            error_msg = f"ERROR: Firmware flash failed: {str(e)}"
            output_queue.put(('add_line', error_msg))
            self.call_from_thread(self.notify, f"Firmware flash failed: {str(e)}", severity="error")
        # try:
        #     with open(firmware_path, 'rb') as f:
        #         firmware_data = f.read()

        #     # Call write_esp_flash with the binary data instead of the file path
        #     write_esp_flash(port, baud_rate, flash_offset, erase_eeprom, firmware_data)

        #     queue_capture.flush()
        #     output_queue.put(('add_line', "Firmware flash completed successfully!"))
        #     time.sleep(0.5)
        #     self.call_from_thread(self.notify, "Firmware flash completed!", severity="information")

        # except Exception as e:
        #     error_msg = f"ERROR: Firmware flash failed: {str(e)}"
        #     output_queue.put(('add_line', error_msg))
        #     self.call_from_thread(self.notify, f"Firmware flash failed: {str(e)}", severity="error")

        finally:
            monitor_running.clear()
            sys.stdout = old_stdout
            time.sleep(0.1)

    def handle_flash_firmware(self) -> None:
        try:
            port = self.query_one("#port-input-flasher", Input).value.strip()
            flash_offset = self.query_one("#flash-address-input", Input).value.strip()
            firmware_path = self.query_one("#name-input-flasher", Input).value.strip()

            # Get baud rate
            baud_rate = None
            baud_buttons = ["flasher-baud-115200", "flasher-baud-460800", "flasher-baud-921600"]
            baud_values = [115200, 460800, 921600]

            for i, button_id in enumerate(baud_buttons):
                try:
                    button = self.query_one(f"#{button_id}", RadioButton)
                    if button.value:
                        baud_rate = baud_values[i]
                        break
                except:
                    pass

            # Get EEPROM erase setting
            erase_eeprom = None
            eeprom_buttons = ["not-erase-eeprom-flasher", "erase-eeprom-flasher"]
            eeprom_values = ["No", "Yes"]
            for j, eeprom_id in enumerate(eeprom_buttons):
                try:
                    eeprom_button = self.query_one(f"#{eeprom_id}", RadioButton)
                    if eeprom_button.value:
                        erase_eeprom = eeprom_values[j]
                        break
                except:
                    pass
            self.notify(f"Erase EEPROM: {eeprom_id}")
            self.notify(f"Erase EEPROM: {erase_eeprom}")
            # Validate inputs
            if not port:
                self.notify("Please enter a port name", severity="error")
                return
            if not baud_rate:
                self.notify("Please select a baud rate", severity="error")
                return
            if not flash_offset:
                self.notify("Please enter flash offset", severity="error")
                return
            if not firmware_path:
                self.notify("Please enter firmware path", severity="error")
                return

            try:
                flash_offset = int(flash_offset, 16) if flash_offset.startswith('0x') else int(flash_offset)
            except ValueError:
                self.notify("Invalid flash offset format", severity="error")
                return

            output_area = self.query_one("#flasher-output", TextArea)
            output_area.text = "Starting firmware flash...\n"

            thread = threading.Thread(
                target=self._flash_firmware_worker,
                args=(port, baud_rate, flash_offset, firmware_path,  erase_eeprom)
            )
            thread.daemon = True
            thread.start()

        except Exception as e:
            self.notify(f"Error: {str(e)}", severity="error")
