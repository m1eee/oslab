# commands/Makefile

#ENTRYPOINT	= 0x1000
HD		= ../80m.img

ASM		= nasm
DASM		= objdump
CC		= gcc
LD		= ld
ASMFLAGS	= -I ../include/ -f elf
CFLAGS		= -I ../include/ -I ../include/sys/ -c -fno-builtin -fno-stack-protector -Wall
LDFLAGS		= -Ttext 0x1000
DASMFLAGS	= -D
LIB		= ../lib/orangescrt.a
BIN		= echo pwd ls open kill touch rm ps syslogd dmesg

# All Phony Targets
.PHONY : everything final clean realclean disasm all install

# Default starting position
everything : $(BIN)

install : all clean
	cp ../boot/hd*.bin ./ -v
	cp ../kernel.bin ./ -v
	tar vcf inst.tar kernel.bin $(BIN) hd*.bin
	dd if=inst.tar of=$(HD) seek=`echo "obase=10;ibase=16;(\`egrep -e '^ROOT_BASE' ../boot/include/load.inc | sed -e 's/.*0x//g'\`+\`egrep -e '#define[[:space:]]*INSTALL_START_SECT' ../include/sys/config.h | sed -e 's/.*0x//g'\`)*200" | bc` bs=1 count=`ls -l inst.tar | awk -F " " '{print $$5}'` conv=notrunc

all : realclean everything

final : all clean

clean :
	rm -f *.o

realclean :
	rm -f $(BIN) *.o

kernel.bin :
	cp ../kernel.bin ./

start.o : start.asm
	$(ASM) $(ASMFLAGS) -o $@ $<

syslogd.o: syslogd.c ../include/cmd_head.h
	$(CC) $(CFLAGS) -o $@ $<

syslogd : syslogd.o start.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $?

echo.o: echo.c ../include/cmd_head.h 
	$(CC) $(CFLAGS) -o $@ $<

echo : echo.o start.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $?

pwd.o: pwd.c ../include/cmd_head.h 
	$(CC) $(CFLAGS) -o $@ $<

pwd : pwd.o start.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $?

ls.o: ls.c ../include/cmd_head.h  
	$(CC) $(CFLAGS) -o $@ $<
ls : ls.o start.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $?

open.o: open.c ../include/cmd_head.h
	$(CC) $(CFLAGS) -o $@ $<
open : open.o start.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $?

kill.o: kill.c ../include/cmd_head.h
	$(CC) $(CFLAGS) -o $@ $<
kill : kill.o start.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $?

touch.o: touch.c ../include/cmd_head.h
	$(CC) $(CFLAGS) -o $@ $<
touch : touch.o start.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $?

rm.o: rm.c ../include/cmd_head.h
	$(CC) $(CFLAGS) -o $@ $<
rm : rm.o start.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $?

ps.o: ps.c ../include/cmd_head.h
	$(CC) $(CFLAGS) -o $@ $<
ps : ps.o start.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $?

dmesg.o: dmesg.c ../include/cmd_head.h
	$(CC) $(CFLAGS) -o $@ $<
dmesg : dmesg.o start.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $?

