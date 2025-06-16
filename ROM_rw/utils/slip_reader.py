from . import FatalError

def slip_reader(port, trace_function):
    partial_packet = None
    in_escape = False
    while True:
        waiting = port.inWaiting()
        read_bytes = port.read(1 if waiting == 0 else waiting)
        if read_bytes == b'':
            waiting_for = "header" if partial_packet is None else "content"
            trace_function("Timed out waiting for packet %s", waiting_for)
            raise FatalError("Timed out waiting for packet %s" % waiting_for)
        trace_function("Read %d bytes: %r", len(read_bytes), read_bytes)
        for b in read_bytes:
            if type(b) is int:
                b = bytes([b])

            if partial_packet is None:
                if b == b'\xc0':
                    partial_packet = b""
                else:
                    trace_function("Read invalid data: %r", read_bytes)
                    trace_function("Remaining data in serial buffer: %r", port.read(port.inWaiting()))
                    raise FatalError('Invalid head of packet (%r)' % b)
            elif in_escape:
                in_escape = False
                if b == b'\xdc':
                    partial_packet += b'\xc0'
                elif b == b'\xdd':
                    partial_packet += b'\xdb'
                else:
                    trace_function("Read invalid data: %r", read_bytes)
                    trace_function("Remaining data in serial buffer: %r", port.read(port.inWaiting()))
                    raise FatalError('Invalid SLIP escape (%r%r)' % (b'\xdb', b))
            elif b == b'\xdb':
                in_escape = True
            elif b == b'\xc0':
                trace_function("Full packet: %r", partial_packet)
                yield partial_packet
                partial_packet = None
            else:
                partial_packet += b
