package wireguardconf

import (
   "testing"
)

func Test(t *testing.T) {
   wg := New("wireguard.conf")
   err := wg.Load()
   if err != nil {
      t.Fatal(err)
   }

   peer, err := wg.Add("new endpoint")
   if err != nil {
      t.Fatal(err)
   }

   err = wg.Append(peer)
   if err != nil {
      t.Fatal(err)
   }
}
