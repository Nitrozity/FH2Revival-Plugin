// ServerAddress.h
//
// Revival server address for this build.  The public source ships with no server (both values 0), so it builds as is.
// To build with a built-in server, put your own address here on your own PC.  Do not commit your real address.
//
// The plugin stores the IPv4 address as two 32-bit numbers, ENC = address XOR XOR_KEY (address as a
// big-endian number: a.b.c.d = (a<<24)|(b<<16)|(c<<8)|d).  Any XOR_KEY works, including 0.
//
// Example for 192.168.1.50 with no obfuscation:
//     192.168.1.50 = 0xC0A80132
//     #define FH2_BAKED_REAL_IP_XOR 0x00000000UL
//     #define FH2_BAKED_REAL_IP_ENC 0xC0A80132UL
//
// Both values 0 = no built-in server.  The plugin then connects only to the address given by
// "ServerIp" in FH2Revival.ini, so a build made from the public source works against any server you point it at.
#define FH2_BAKED_REAL_IP_XOR 0x00000000UL
#define FH2_BAKED_REAL_IP_ENC 0x00000000UL
