package wireguardconf

import (
   "net/netip"
)

type Interface struct {
   Address    netip.Addr
   Mask       int
   ListenPort int
   PrivateKey string
   PublicKey  string
   MTU        string
}

type Peer struct {
   Comment      string
   PrivateKey   string
   PublicKey    string
   PresharedKey string
   AllowedIP    netip.Addr
   Mask         int
}

type Wireguard struct {
   Filename  string
   Interface Interface
   Peers     []Peer
}
