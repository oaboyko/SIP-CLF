JCFLAGS=-cp ./lib/jnetpcap.jar
JFLAGS=-cp .:./lib/jnetpcap.jar


all:	
	@javac $(JCFLAGS) SIPCLFGenerator.java	

run:	SIPCLFGenerator.class
	@sudo java $(JFLAGS) SIPCLFGenerator

clean:
	@rm -f SIPCLFGenerator*.class
