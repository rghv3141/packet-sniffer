# packet-sniffer
The packet sniffer is built on Linux AF_PACKET raw sockets, allowing direct access to Layer 2 Ethernet frames without relying on higher-level networking APIs.

To reduce unnecessary packet processing in user space, the program attaches handwritten Classic Berkeley Packet Filter (cBPF) bytecode to the socket using SO_ATTACH_FILTER. The kernel evaluates the filter before delivering packets to the application, ensuring that only packets relevant to the selected operating mode are captured.

The application supports 4 operating mode

| Mode |	Description |
|------|--------------|
| capture |	Captures and displays both TCP and UDP packets.|
| tcp	| Tracks TCP connections and maintains a simplified TCP state machine.|
| talkers	| Records traffic statistics and reports the top 10 talkers by byte count when the program exits.|
|scan |	Detects SYN port scans by tracking unique destination ports contacted by each source IP address.|
