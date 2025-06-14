import r2pipe
import os

def disassemble_esp8266_full(firmware_path):
    if not os.path.exists(firmware_path):
        return f"Error: File {firmware_path} not found"
    
    file_size = os.path.getsize(firmware_path)
    print(f"Firmware size: {file_size} bytes ({file_size/1024:.1f} KB)")

    r2 = r2pipe.open(firmware_path)
    
    try:
        r2.cmd('e log.level=0') 
        r2.cmd('e scr.interactive=false') 
        r2.cmd('e scr.prompt=false')
        r2.cmd('e cfg.fortunes=false') 
        r2.cmd('e cfg.debug=false') 
        r2.cmd('e anal.verbose=false')
 
        r2.cmd('e asm.arch=xtensa')
        r2.cmd('e asm.bits=32')
        r2.cmd('e cfg.bigendian=false')
        r2.cmd('e anal.armthumb=false')
        r2.cmd('e anal.strings=true')
        r2.cmd('e io.cache=true')  
        r2.cmd('e anal.hasnext=true')
        r2.cmd('e anal.depth=256')
        r2.cmd('e anal.timeout=300')
        r2.cmd('e asm.bytes=false')
        r2.cmd('e asm.comments=true')
        r2.cmd('e asm.lines=false')
        r2.cmd('e asm.refptr=false')
        r2.cmd('e asm.cmt.right=false')
        
        r2.cmd(f'omr 0x40000000 {file_size} rwx')
        r2.cmd('s 0x40000000')
        
        r2.cmd('aa')
        r2.cmd('aac')

        functions_json = r2.cmdj('aflj')
        
        if not functions_json:
            print("No functions found. Trying alternative analysis...")
            r2.cmd('e anal.from=0x40000000')
            r2.cmd('e anal.to=0x40000000+' + str(file_size))
            r2.cmd('af @@ sym.*')
            functions_json = r2.cmdj('aflj')
        
        result = []
        if functions_json:
            for func in functions_json:
                try:
                    offset = func.get('offset', 0)
                    name = func.get('name', 'unknown')
                    size = func.get('size', 0)
                    
                    result.append(f"\n{'='*60}")
                    result.append(f"\nFunction: {name} @ {hex(offset)}")
                    result.append(f"Size: {size} bytes")

                    r2.cmd(f's {offset}')
                    asm = r2.cmd(f'pdf @ {offset}')
                    if asm:
                        result.append("\nAssembly:")
                        result.append("-"*40)
                        result.append(asm)
                    else:
                        result.append("\nWarning: Could not disassemble function")
                                        
                except Exception as e:
                    result.append(f"\nError processing function {name}: {str(e)}")
                    continue
        else:
            return "No functions were found in the firmware.\nThe analysis may have failed."
        
        return '\n'.join(result)
        
    except Exception as e:
        return f"Error during disassembly: {e}"
    finally:
        r2.quit()

def save_disassembly_to_file(firmware_path, output_file="disassembly.txt"):

    print(f"Disassembling {firmware_path}...")
    result = disassemble_esp8266_full(firmware_path)
    
    with open(output_file, 'w') as f:
        f.write(f"ESP8266 Firmware Disassembly and C Pseudocode: {firmware_path}\n")
        f.write("=" * 60 + "\n\n")
        f.write(result)
    
    print(f"Disassembly and C pseudocode saved to {output_file}")
    return result

def disassemble_esp8266_chunked(firmware_path, chunk_size=1000):
    if not os.path.exists(firmware_path):
        return f"Error: File {firmware_path} not found"
    
    file_size = os.path.getsize(firmware_path)
    r2 = r2pipe.open(firmware_path)
    
    try:

        r2.cmd('e log.level=0')
        r2.cmd('e scr.interactive=false')
        r2.cmd('e scr.prompt=false')
        r2.cmd('e cfg.fortunes=false')
        r2.cmd('e cfg.debug=false')
        r2.cmd('e anal.verbose=false')
        
        r2.cmd('e asm.arch=xtensa')
        r2.cmd('e asm.bits=32')
        r2.cmd('e cfg.bigendian=false')
        r2.cmd('e anal.armthumb=false')
        r2.cmd('e anal.strings=true')
        r2.cmd('e io.cache=true')
        r2.cmd('e anal.hasnext=true')
        r2.cmd('e anal.depth=256')
        r2.cmd('e anal.timeout=300')
        r2.cmd('e asm.bytes=false')
        r2.cmd('e asm.comments=true')
        r2.cmd('e asm.lines=false')
        r2.cmd('e asm.refptr=false')
        r2.cmd('e asm.cmt.right=false')
        
        r2.cmd(f'om 3 0x40000000 0x{file_size:x} 0x0 rwx')
        r2.cmd('s 0x40000000')
        r2.cmd('aaa')
        
        functions = r2.cmdj('aflj')
        full_disasm = []
        
        if functions:
            for i, func in enumerate(functions):
                full_disasm.append(f"\n{'='*60}")
                full_disasm.append(f"\nFunction: {func['name']} @ {hex(func['offset'])}")
                r2.cmd(f's {func["offset"]}')
                asm = r2.cmd(f'pdf @ {func["offset"]}')
                full_disasm.append("\nAssembly:")
                full_disasm.append("-"*40)
                full_disasm.append(asm)
                
                pseudo_c = r2.cmd(f'pdc @ {func["offset"]}')
                full_disasm.append("\nC Pseudocode:")
                full_disasm.append("-"*40)
                full_disasm.append(pseudo_c if pseudo_c.strip() else "// Decompilation not available")
                
                progress = ((i + 1) / len(functions)) * 100
                print(f"\rProgress: {progress:.1f}%", end='', flush=True)
        
        print("\nDisassembly complete!")
        return '\n'.join(full_disasm)
        
    finally:
        r2.quit()
