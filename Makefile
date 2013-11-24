JCFLAGS=-cp jnetpcap.jar
JFLAGS=-cp .:jnetpcap.jar


all:	
	@javac $(JCFLAGS) Capturer.java	

run:	Capturer.class
	@sudo java $(JFLAGS) Capturer

clean:
	@rm -f Capturer*.class
