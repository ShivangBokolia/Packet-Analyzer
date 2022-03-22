/**
 * @author: Shivang Bokolia
 * class: CSCI 651: Foundations of Computer Networks
 */

import java.io.*;

public class pktanalyzer {
    private DataInputStream byteInput;
    private long inputSize;
    private boolean hasIPHeader = false;
    private int protocol;

    /**
     * The main method for calling the packet analyzer function.
     * The method takes in the packet file and stores the data using
     * DataInputStream for easier access to the byte data in the file.
     * @param args
     */
    public static void main(String[] args){
        // Checking whether the file is provided by the user or not.
        if (args.length != 1){
            System.out.println("Please enter a file name!");
            System.exit(0);
        }

        // Creating an object to call the class's methods and access it's
        // variables.
        pktanalyzer packet = new pktanalyzer();

        // Reading in the packet file and storing the data in a variable called
        // byteInput to access it at a later point.
        try{
            File inputFile = new File(args[0]);
            InputStream input_stream = new FileInputStream(inputFile);
            packet.byteInput= new DataInputStream(input_stream);
            packet.inputSize = inputFile.length();

            packet.packetAnalyzer();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * This is the method that generates the Ethernet header, IP header and protocol header
     * depending on the file provided.
     * @throws IOException
     */
    private void packetAnalyzer() throws IOException{
        // Printing the Ethernet header:
        etherHeader();
        // Checking if the file has an IP header or not and printing out the header if it does.
        if (hasIPHeader){
            IPHeader();
        }
        // Checking the protocol the file follows and printing out the respective header.
        // 1 --> ICMP
        // 6 --> TCP
        // 17 --> UDP
        if (protocol == 1){
            ICMPHeader();
        } else if (protocol == 6){
            TCPHeader();
        } else if (protocol == 17){
            UDPHeader();
        }
    }

    /**
     * This function prints out the Ethernet header by reading the bytes in the file
     * using the helper functions.
     * @throws IOException
     */
    private void etherHeader () throws IOException{
        System.out.println("ETHER: ----- Ether Header -----");
        System.out.println("ETHER:");
        System.out.format("ETHER: Packet Size = %d bytes\n", inputSize);
        System.out.format("ETHER: Destination = ");
        getAddress();
        System.out.format("ETHER: Source = ");
        getAddress();
        System.out.format("ETHER: Ethertype = ");
        getEtherType();
        System.out.println("ETHER:");
    }

    /**
     * This function prints out the IP header by reading the bytes in the file
     * using the helper functions.
     * @throws IOException
     */
    private void IPHeader() throws IOException{
        System.out.println("IP: \t----- IP Header -----");
        System.out.println("IP:");
        int headerLength = getVersionAndLength();
        getTypeOfService();
        System.out.format("IP: \tTotal Length = %d bytes\n", (byteInput.read() << 8) | byteInput.read());
        System.out.format("IP: \tIdentification = %d\n", (byteInput.read() << 8) | byteInput.read());
        getFlagsAndFragment();
        System.out.format("IP: \tTime To Live = %d seconds/hops\n", byteInput.read());
        protocol = getProtocol();
        System.out.format("IP: \tHeader Checksum = %s\n", getChecksum());
        getSourceDestinationAddress("Source");
        getSourceDestinationAddress("Destination");
        if (headerLength <= 20){
            System.out.println("IP: \tNo options");
        } else {
            System.out.println("IP: \tOptions Available");
        }
        System.out.println("IP:");
    }

    /**
     * The function prints the ICMP header by reading the bytes in the file
     * using the helper functions.
     * @throws IOException
     */
    private void ICMPHeader() throws IOException{
        System.out.println("ICMP: \t----- ICMP Header -----");
        System.out.println("ICMP:");
        getICMPType();
        System.out.format("ICMP: \tCode = %d\n", byteInput.read());
        System.out.format("ICMP: \tChecksum = %s\n", getChecksum());
        System.out.println("ICMP:");
    }

    /**
     * This function prints the TCP header by reading the bytes in the file
     * using the helper functions.
     * @throws IOException
     */
    private void TCPHeader() throws IOException{
        System.out.println("TCP: \t----- TCP Header -----");
        System.out.println("TCP:");
        System.out.format("TCP: \tSource port = %d\n", (byteInput.read() << 8 | byteInput.read()));
        System.out.format("TCP: \tDestination port = %d\n", (byteInput.read() << 8 | byteInput.read()));
        System.out.format("TCP: \tSequence number = %d\n", getSeqAndAckNumber());
        System.out.format("TCP: \tAcknowledgement number = %d\n", getSeqAndAckNumber());
        int dataOffset = getTCPFlagsAndOffset();
        System.out.format("TCP: \tWindow = %d\n", (byteInput.read() << 8 | byteInput.read()));
        System.out.format("TCP: \tChecksum = %s\n", getChecksum());
        System.out.format("TCP: \tUrgent pointer = %d\n", (byteInput.read() << 8 | byteInput.read()));
        if (dataOffset > 20){
            System.out.println("TCP: \tThere are options");
        } else {
            System.out.println("TCP: \tNo options");
        }
        System.out.println("TCP:");
        System.out.println("TCP: \tData: (first 64 bytes)");
        get64BytesData("TCP");
    }

    /**
     * This function prints the UDP header by reading the bytes in the file
     * using the helper functions.
     * @throws IOException
     */
    private void UDPHeader() throws IOException{
        System.out.println("UDP: \t----- UDP Header -----");
        System.out.println("UDP: ");
        System.out.format("UDP: \tSource port = %d\n", (byteInput.read() << 8 | byteInput.read()));
        System.out.format("UDP: \tDestination port = %d\n", (byteInput.read() << 8 | byteInput.read()));
        System.out.format("UDP: \tLength = %d\n", (byteInput.read() << 8 | byteInput.read()));
        System.out.format("UDP: \tChecksum = %s\n", getChecksum());
        System.out.println("UDP: ");
        System.out.println("UDP: \tData: (first 64 bytes)");
        get64BytesData("UDP");
    }

    /*
    ******************************** HELPER FUNCTIONS ********************************
     */

    /**
     * This function helps in getting the 6 bytes Destination and source address from the
     * file provided.
     * @throws IOException
     */
    private void getAddress () throws IOException {
        StringBuilder address = new StringBuilder();
        for (int i = 0; i < 6; i++){
            int byteValue = byteInput.read();
            String hexValue = Integer.toHexString(byteValue);
            if (hexValue.length() == 1){
                hexValue = "0" + hexValue;
            }
            if (i == 5){
                address.append(hexValue).append(",");
            } else {
                address.append(hexValue).append(":");
            }
        }
        System.out.println(address);
    }

    /**
     * This function helps in checking whether the Ethernet header consists of the IP or not.
     * If it does, it prints out the IP along with the type else prints No IP.
     * @throws IOException
     */
    private void getEtherType () throws IOException{
        StringBuilder etherType = new StringBuilder();
        for (int i = 0; i < 2; i++){
            int byteValue = byteInput.read();
            String hexValue = Integer.toHexString(byteValue);
            if (hexValue.length() == 1){
                hexValue = "0" + hexValue;
            }
            etherType.append(hexValue);
        }
        if (etherType.toString().equals("0800")){
            etherType.append(" (IP)");
            // Setting the boolean for the file consisting of IP Header to be true.
            hasIPHeader = true;
        } else if (etherType.toString().equals("0806")){
            etherType.append(" (ARP)");
            // Setting the boolean for the file consisting of IP Header to be true.
            hasIPHeader = true;
        } else {
            etherType.append(" (Other Not IP)");
        }
        System.out.println(etherType);
    }

    /**
     * Function for reading in the first byte of the IP header and getting the version and length
     * from the same.
     * @return the length of the IP packet.
     * @throws IOException
     */
    private int getVersionAndLength() throws IOException {
        int versionAndLenght = byteInput.read();
        int version = versionAndLenght >> 4;
        System.out.format("IP: \tVersion = %d\n", version);
        byte getLength = (byte) 15;
        int length = versionAndLenght & getLength;
        length = length << 2;
        System.out.format("IP: \tHeader Length = %d bytes\n", length);
        return length;
    }

    /**
     * This function checks the DSCP and ECN for the type of service from the packet.
     * @throws IOException
     */
    private void getTypeOfService() throws IOException {
        int dscp = byteInput.read();
        String tosHexValue = Integer.toHexString(dscp);
        if (tosHexValue.length() == 1){
            tosHexValue = "0" + tosHexValue;
        }
        System.out.println("IP: \tType of service = 0x" + tosHexValue);
        System.out.println("IP: \t\txxx. .... = 0 (precedence)");
        System.out.println(((dscp & (1 << 5)) == (1 << 5)) ?
                "IP: \t\t...1 .... = low delay" : "IP: \t\t...0 .... = normal delay");
        System.out.println(((dscp & (1 << 4)) == (1 << 4)) ?
                "IP: \t\t.... 1... = high throughput" : "IP: \t\t.... 0... = normal throughput");
        System.out.println(((dscp & (1 << 3)) == (1 << 3)) ?
                "IP: \t\t.... .1.. = high reliability" : "IP: \t\t.... .0.. = normal reliability");
    }

    /**
     * This function gets the 3 bit flag value and reads the 13 bit value for the flag offset.
     * @throws IOException
     */
    private void getFlagsAndFragment() throws IOException{
        int firstHalf = byteInput.read();
        int flag = firstHalf >>> 5;
        int fragOffset = firstHalf & 0b11111;
        int secondHalf = byteInput.read();
        System.out.format("IP: \tFlags = 0x%d\n", flag);
        if (flag == 0){
            System.out.println("IP: \t\t.0.. .... = OK to fragment");
            System.out.println("IP: \t\t..0. .... = last fragment");
        } else if ((flag & 0b010) == 0b010){
            System.out.println("IP: \t\t.1.. .... = do not fragment");
            System.out.println("IP: \t\t..0. .... = last fragment");
        } else if ((flag & 0b001) == 0b001){
            System.out.println("IP: \t\t.0.. .... = OK to fragment");
            System.out.println("IP: \t\t..1. .... = more fragments");
        }
        fragOffset = (fragOffset << 5) | secondHalf;
        System.out.format("IP: \tFragment offset = %d bytes\n", fragOffset);
    }

    /**
     * This function is used to get the protocol for the packet file provided; The function
     * identifies 3 protocols: ICMP, TCP and UDP.
     * @return It returns the protocol number derived from the packet file.
     * @throws IOException
     */
    private int getProtocol() throws IOException{
        int protocol = byteInput.read();
        if (protocol == 1){
            System.out.format("IP: \tProtocol = %d (ICMP)\n", protocol);
        } else if (protocol == 6){
            System.out.format("IP: \tProtocol = %d (TCP)\n", protocol);
        } else if (protocol == 17){
            System.out.format("IP: \tProtocol = %d (UDP)\n", protocol);
        } else {
            System.out.format("IP: \tProtocol = %d (ARP)\n", protocol);
        }
        return protocol;
    }

    /**
     * This function is used to obtain the checksum provided in the IP Header using ]
     * bit manipulation.
     * @return the hex string value of the checksum.
     * @throws IOException
     */
    private StringBuilder getChecksum() throws IOException{
        StringBuilder checksum = new StringBuilder();
        checksum.append("0x");
        for (int i=0; i<2; i++){
            String checksumHexValue = Integer.toHexString(byteInput.read());
            if (checksumHexValue.length() == 1){
                checksumHexValue = "0" + checksumHexValue;
            }
            checksum.append(checksumHexValue);
        }
        return checksum;
    }

    /**
     * The function reads the bytes from the packet and obtains the source and destination address.
     * @param type (the type of address, destination or source)
     * @throws IOException
     */
    private void getSourceDestinationAddress(String type) throws IOException{
        System.out.format("IP: \t%s address = %d",type, byteInput.read());
        for (int i=0; i<3; i++){
            System.out.format(".%d", byteInput.read());
        }
        System.out.println();
    }

    /**
     * This function provides the ICMP type filed and checks whether it was an Echo request or an
     * Echo reply or any other type.
     * @throws IOException
     */
    private void getICMPType() throws IOException{
        int ICMPtype = byteInput.read();
        System.out.format("ICMP: \tType = %d", ICMPtype);
        if (ICMPtype == 8) {
            System.out.println(" (Echo Request)");
        } else if (ICMPtype == 0){
            System.out.println(" (Echo Reply)");
        } else {
            System.out.println();
        }
    }

    /**
     * This function gets the sequence and the acknowledgement number from the bytes provided in
     * the file. We need to use the long data structure because the number needs to be positive and
     * cannot be negative.
     * @return returns a long value of the sequence or acknowledgement number.
     * @throws IOException
     */
    private long getSeqAndAckNumber() throws IOException{
        long seq = byteInput.read();
        for (int i=0; i<3; i++){
            seq = (seq << 8 | byteInput.read());
        }
        return seq;
    }

    /**
     * This function gets the Flags and the offset from the bytes in the packet file.
     * The values of all the flags are obtained using bit manipulaiton one-by-one.
     * @return returns the data offset value to check whether the options for the
     * TCP header has been provided or not.
     * @throws IOException
     */
    private int getTCPFlagsAndOffset() throws IOException{
        int offset = byteInput.read() >> 4;
        System.out.format("TCP: \tData offset = %d bytes\n", offset);
        int flags = byteInput.read();
        System.out.format("TCP: \tFlags = 0x%d\n", flags);
        System.out.println(((1 << 7) & flags) == (1 << 7) ?
                "TCP: \t\t1... .... = CWR" : "TCP: \t\t0... .... = No CWR");
        System.out.println((flags & (1 << 6)) == (1 << 6) ?
                "TCP: \t\t.1.. .... = ECE" : "TCP: \t\t.0.. .... = No ECE");
        System.out.println((flags & (1 << 5)) == (1 << 5) ?
                "TCP: \t\t..1. .... = Urgent Pointer" : "TCP: \t\t..0. .... = No Urgent Pointer");
        System.out.println((flags & (1 << 4)) == (1 << 4) ?
                "TCP: \t\t...1 .... = Acknowledgement" : "TCP: \t\t...0 .... = No Acknowledgement");
        System.out.println((flags & (1 << 3)) == (1 << 3) ?
                "TCP: \t\t.... 1... = Push" : "TCP: \t\t.... 0... = No Push");
        System.out.println((flags & (1 << 2)) == (1 << 2) ?
                "TCP: \t\t.... .1.. = Reset" : "TCP: \t\t.... .0.. = No Reset");
        System.out.println((flags & (1 << 1)) == (1 << 1) ?
                "TCP: \t\t.... ..1. = Syn" : "TCP: \t\t.... ..0. = No Syn");
        System.out.println((flags == 0b1) ?
                "TCP: \t\t.... ...1 = Fin" : "TCP: \t\t.... ...0 = No Fin");
        return offset;
    }

    /**
     * This function provides info on the 64 bytes data that is provided for the TCP and
     * UDP header. If the packet consists of less than 64 bytes of data, the function halts and
     * only prints the number of bytes that are present.
     * The function also provides the char representation of the byte values using the ascii values
     * as a limiter. If the byte values are over the ascii value, the char representation is switched
     * with a "."
     * @param type
     * @throws IOException
     */
    private void get64BytesData(String type) throws IOException{
        int bytes = 0;
        StringBuilder charString = new StringBuilder();
        System.out.format("%s: \t", type);
        while (bytes < 64){
            int byteIntVal = byteInput.read();
            String byteHexVal = Integer.toHexString(byteIntVal);
            if (byteHexVal.length() == 1){
                byteHexVal = "0" + byteHexVal;
            }
            if (byteIntVal == -1){
                break;
            }
            if (bytes % 2 == 0 && bytes != 0){
                System.out.print(" ");
            }
            if (bytes % 16 == 0 && bytes != 0){
                System.out.format("\t\t'%s'\n", charString);
                System.out.format("%s: \t", type);
                charString = new StringBuilder();
            }
            System.out.format("%s", byteHexVal);
            if ((byteIntVal >= 65) && (byteIntVal <= 122)){
                charString.append((char)byteIntVal);
            } else{
                charString.append(".");
            }
            bytes += 1;
        }
        System.out.print(" ");
        System.out.format("\t\t'%s'\n", charString);
    }
}
