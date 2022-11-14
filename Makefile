all: PacketAnalyzer

logger.o: logger.c
	$(CC) -Wall -c logger.c

process_packet.o: process_packet.c
	$(CC) -Wall -c process_packet.c

PacketAnalyzer: main.c logger.o process_packet.o
	$(CC) main.c logger.o process_packet.o -ggdb -o PacketAnalyzer
	sudo chown root PacketAnalyzer
	sudo chmod +s PacketAnalyzer

clean:
	rm -f *.o PacketAnalyzer
