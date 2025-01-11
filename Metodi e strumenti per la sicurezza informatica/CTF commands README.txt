CTF commands README:

Se abbiamo a disposizione il sorgente del file lo compiliamo senza i criteri di sicurezza:
gcc file_name.c -o file -fno-stack-protector -z execstack -no-pie -m32 -> compila il file senza criteri di sicurezza

Sennò partiamo direttamente da qui:
file file_name -> info sul file (architettura, bit, ecc)
checksec --file file_name -> mostra i criteri di sicurezza del file
ltrace ./file_name -> mostra l'esecuzione real time della strada percorsa dalle stringhe o dal programma, da vedere come un real-time disassembler

BUFFER OVERFLOW
Prima cosa da fare è provare ignorantemente a inserire un numero di caratteri a caso scelti da noi per fare buffer overflow.
Un esempio potrebbe essere durante l'esecuzione di un file che chiede una password inserire "aaaaaaaa" e quando abbiamo ottenuto "segmentation fault" ridurre il 
numero di caratteri.

GHIDRA
ghidra_auto file_name -> crea automaticamente un progetto con quel file eseguibile.