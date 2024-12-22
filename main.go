package wireguardconf

import (
   "errors"
   "fmt"
   "os"
   "regexp"
   "strconv"
)

var (
   reInterface = regexp.MustCompile(`\[Interface\]\nAddress = ([\d\.]+)/(\d+)\nListenPort = (\d+)\nPrivateKey = (\S{44})\nMTU = (\d+)`)
   rePeer = regexp.MustCompile(`# [^\n]+\n\[Peer\]\nPublicKey = (\S{44})\nAllowedIPs = ([\d\.]+)/(\d+)[^\n]*\nPresharedKey = (\S{44})\n`)
)

type Interface struct {
   Address    string
   Mask       int
   ListenPort int
   PrivateKey string
   MTU        string
}

type Peer struct {
   PublicKey    string
   AllowedIP    string
   Mask         int
   PresharedKey string
}

type Wireguard struct {
   Filename  string
   Interface Interface
   Peers     []Peer
}

func New(fname string) *Wireguard {
   return &Wireguard{
      Filename: fname,
   }
}

func (wg *Wireguard) Load() error {
   content, err := os.ReadFile(wg.Filename)
   if err != nil {
      return fmt.Errorf("Load: %w", err)
   }

   m := reInterface.FindSubmatch(content)
   if len(m) == 0 {
      return errors.New("Load: no 'interface' section")
   }

   wg.Interface.Address = string(m[1])
   wg.Interface.Mask, err = strconv.Atoi(string(m[2]))
   if err != nil {
      return fmt.Errorf("Load: %w", err)
   }

   wg.Interface.ListenPort, err = strconv.Atoi(string(m[3]))
   if err != nil {
      return fmt.Errorf("Load: %w", err)
   }

   wg.Interface.PrivateKey = string(m[4])
   wg.Interface.MTU        = string(m[5])

   for _, m := range rePeer.FindAllSubmatch(content[:], -1) {
      peer := Peer{
         PublicKey:    string(m[1]),
         AllowedIP:    string(m[2]),
         PresharedKey: string(m[4]),
      }

      peer.Mask, err = strconv.Atoi(string(m[3]))
      if err != nil {
         return fmt.Errorf("Load: %w", err)
      }

      wg.Peers = append(wg.Peers, peer)
   }

   return nil
}
