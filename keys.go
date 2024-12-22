package wireguardconf

import (
   "bytes"
   "fmt"
   "os/exec"
   "strings"
)

func genPrivKey() (string, error) {
   out, err := exec.Command("wg", "genkey").Output()
   if err != nil {
      return "", fmt.Errorf("genPrivkey: %w", err)
   }

   return strings.TrimSpace(string(out)), nil
}

func genPresharedKey() (string, error) {
   out, err := exec.Command("wg", "genpsk").Output()
   if err != nil {
      return "", fmt.Errorf("genPresharedKey: %w", err)
   }

   return strings.TrimSpace(string(out)), nil
}

func derivePubKey(privkey string) (string, error) {
   cmd := exec.Command("wg", "pubkey")
   cmd.Stdin = strings.NewReader(privkey)

   var stdout bytes.Buffer
   cmd.Stdout = &stdout

   err := cmd.Run()
   if err != nil {
      return "", fmt.Errorf("derivePublicKey: %w", err)
   }

   return strings.TrimSpace(stdout.String()), nil
}
