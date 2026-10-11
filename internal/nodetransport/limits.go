// Package nodetransport contains resource bounds shared by the node control
// channel endpoints. It deliberately has no application or runtime imports.
package nodetransport

import "github.com/coder/websocket"

// ControlMessageLimit bounds one JSON control-channel websocket message at
// both ends of the controller/node connection.
const ControlMessageLimit int64 = 4 << 20

// ApplyControlMessageLimit configures a newly accepted or dialed connection
// before its first application message is read.
func ApplyControlMessageLimit(conn *websocket.Conn) {
	conn.SetReadLimit(ControlMessageLimit)
}
