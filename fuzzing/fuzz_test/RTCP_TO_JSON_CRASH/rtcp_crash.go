package main

import(
	"net"
)

func main() {
	dat := []byte{
		0x81,0xc9,0x00,0x07,0x00,0x00,0x00,0x01,0x00,
		0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00}

	conn, _ := net.Dial("udp","127.0.0.1:9000")

	for i := 1; i < 50; i++ {
		conn.Write(dat)
	}
}
