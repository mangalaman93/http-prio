package http

import (
	"fmt"
	"net"
	"reflect"
	"syscall"
)

// sets Priority for the TCP connection
func setTCPPriority(conn net.Conn, priority int) error {
	tcon, ok := conn.(*net.TCPConn)
	if !ok {
		uconn := reflect.ValueOf(conn)
		if uconn.Kind() == reflect.Ptr {
			uconn = uconn.Elem()
		}

		if uconn.NumField() > 0 {
			conn := uconn.Field(0).Interface()
			tcon, ok = conn.(*net.TCPConn)
		}

		if !ok {
			return fmt.Errorf("Not a TCP connection!")
		}
	}

	file, err := tcon.File()
	if err != nil {
		return err
	}

	// test wireshark: (syscall.IPPROTO_IP, syscall.IP_TOS, 0x28)
	// if priority != 0 {
	// 	err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_TOS, 0x28)
	// }
	err = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_PRIORITY, priority)
	file.Close()
	if err != nil {
		return err
	}

	return nil
}
