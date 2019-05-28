# Packet analyzer for TCP, UDP and ICMP packet
## Instructions to use:
`$ javac pktanalyzer.java`

`$ java pktanalyzer path/to/.bin`

## Overview
The process will first extract the whole packet into a byte array and process it byte by byte. 
Each function called on the packet unwraps a header file and forwards it to the next protocol header with a modified offset.
