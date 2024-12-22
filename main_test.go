package wireguardconf

import (
   "fmt"
   "testing"
)

func TestNew(t *testing.T) {
   wg := New("wireguard.conf")
   err := wg.Load()
   if err != nil {
      t.Fatal(err)
   }

   fmt.Printf("wg=%+v\n", wg)
}
