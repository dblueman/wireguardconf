package wireguardconf

import (
   "errors"
   "fmt"
   "net/netip"
   "os"
   "regexp"
   "strconv"
)

var (
   reInterface = regexp.MustCompile(`\[Interface\]\nAddress = ([\d\.]+)/(\d+)\nListenPort = (\d+)\nPrivateKey = (\S{44})\nMTU = (\d+)`)
   rePeer = regexp.MustCompile(`# ([^\n]+)\n\[Peer\]\nPublicKey = (\S{44})\nAllowedIPs = ([\d\.]+)/(\d+)[^\n]*\nPresharedKey = (\S{44})\n`)
)

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

   wg.Interface.Address, err = netip.ParseAddr(string(m[1]))
   if err != nil {
      return fmt.Errorf("Load: %w", err)
   }

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
         Comment:      string(m[1]),
         PublicKey:    string(m[2]),
         PresharedKey: string(m[5]),
      }

      peer.AllowedIP, err = netip.ParseAddr(string(m[3]))
      if err != nil {
         return fmt.Errorf("Load: %w", err)
      }

      peer.Mask, err = strconv.Atoi(string(m[4]))
      if err != nil {
         return fmt.Errorf("Load: %w", err)
      }

      wg.Peers = append(wg.Peers, peer)
   }

   return nil
}

func (wg *Wireguard) used(addr netip.Addr) bool {
   for _, peer := range wg.Peers {
      if peer.AllowedIP == addr {
         return true
      }
   }

   return false
}

func (wg *Wireguard) Add(comment string) (*Peer, error) {
   addr := wg.Peers[0].AllowedIP

   for wg.used(addr) {
      addr = addr.Next()
   }

   peer := Peer{
      Comment:   comment,
      AllowedIP: addr,
      Mask:      32,
   }

   var err error
   peer.PresharedKey, err = genPresharedKey()
   if err != nil {
      return nil, fmt.Errorf("Add: %w", err)
   }

   peer.PrivateKey, err = genPrivKey()
   if err != nil {
      return nil, fmt.Errorf("Add: %w", err)
   }

   peer.PublicKey, err = genPubKey(peer.PrivateKey)
   if err != nil {
      return nil, fmt.Errorf("Add: %w", err)
   }

   wg.Peers = append(wg.Peers, peer)
   return &peer, nil
}

func (wg *Wireguard) Append(peer *Peer) error {
   f, err := os.OpenFile(wg.Filename, os.O_WRONLY | os.O_APPEND, 0o600)
   if err != nil {
      return fmt.Errorf("Append: %w", err)
   }

   buf := fmt.Sprintf("\n# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\nPresharedKey = %s\n",
     peer.Comment, peer.PublicKey, peer.AllowedIP.String(), peer.PresharedKey)

   _, err = f.WriteString(buf)
   if err != nil {
      return fmt.Errorf("Append: %w", err)
   }

   err = f.Close()
   if err != nil {
      return fmt.Errorf("Append: %w", err)
   }

   return nil
}
