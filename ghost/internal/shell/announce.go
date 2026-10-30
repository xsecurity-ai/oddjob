package shell

import "encoding/json"

// announcement is what an ARRIVED frame carries.
//
// JSON rather than the bare peer address the single-port version
// sent, because a Ghost holding six ports makes "which listener
// caught this" a question an operator genuinely has -- a shell on
// 443 and a shell on 8080 came back through different egress rules
// and mean different things about the client's network.
//
// The server accepts a bare address too, so a newer server and an
// older Ghost still record sessions. Losing a live shell to a
// version skew would be the worse failure by a long way.
type announcement struct {
	Peer     string `json:"peer"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	//: Whether the Ghost terminated TLS for this connection. One
	//: listener takes both, decided per connection from the first
	//: bytes, so this is a property of the SESSION and not of the
	//: port it arrived on.
	TLS bool `json:"tls,omitempty"`
}

func announce(peer, protocol string, port int) []byte {
	return announceTLS(peer, protocol, port, false)
}

func announceTLS(peer, protocol string, port int, encrypted bool) []byte {
	b, err := json.Marshal(announcement{Peer: peer, Protocol: protocol,
		Port: port, TLS: encrypted})
	if err != nil {
		// Cannot happen for three plain fields, and if it somehow
		// did, the peer address alone is still a session the server
		// can file. Silence here would be a shell nobody records.
		return []byte(peer)
	}
	return b
}
