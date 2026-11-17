# Why OT needs Modbus command semantics
An unauthorised Modbus write is protocol-valid, correct size, and sent to a normal
destination, so it is invisible to a bytes-and-packets flow baseline. Freezing the
normal (src, func, register) command vocabulary is what catches it — 10/10 with
zero false positives — including the compromised-source case.
