# 08 — Browser Compatibility & Agent Testing (Part H)

> **Durata:** 1-1.5h. **Priorità:** 🟠 Alta.
>
> Questa parte verifica che l'UI funzioni sui browser principali e
> che gli agent SentriKat si installino e funzionino sui 3 OS
> supportati (Linux, macOS, Windows).

---

## H.1 Browser compatibility matrix

Minimum supported: **ultimi 2 major version** di ogni browser.

| Browser | Versione test | Note |
|---|---|---|
| Chrome | latest + latest-1 | Target principale |
| Firefox | latest + latest-1 | Secondary target |
| Safari | latest (macOS + iOS) | Macenterprise + BYOD |
| Edge | latest | Windows enterprise |

### H.1.1 Chrome (primary target)
- [ ] Homepage/login → rendering corretto, no console error
- [ ] Login flow funziona
- [ ] Dashboard carica entro 3s con 100 asset
- [ ] Grafici (Chart.js / similar) si renderizzano
- [ ] Tabelle asset con sort/filter/paginate → tutto responsive
- [ ] Modal creazione asset → si apre e salva
- [ ] Drag & drop file upload funziona
- [ ] Export PDF scaricato correttamente
- [ ] Nessun errore nella Chrome DevTools console
- [ ] Nessun warning deprecato grave
- [ ] Lighthouse performance score ≥ 80 su dashboard

### H.1.2 Firefox
- [ ] Stesso percorso di H.1.1
- [ ] CSS grid/flex layout identico a Chrome
- [ ] Font rendering accettabile
- [ ] No regressioni visibili

### H.1.3 Safari (macOS)
- [ ] Login flow
- [ ] Dashboard renderizza (attenzione a `date-fns` + Safari date parsing)
- [ ] Date picker funziona (Safari ha quirks)
- [ ] Upload file `multipart/form-data` OK
- [ ] WebSocket real-time update funziona (se presente)

### H.1.4 Safari (iOS) — read-only minimo
- [ ] Login da iPhone / iPad
- [ ] Dashboard è leggibile (responsive)
- [ ] Navigazione menu hamburger funziona
- [ ] Tabelle scrollabili orizzontalmente
- [ ] Nessun overflow orizzontale involontario
- [ ] Touch target ≥ 44px su bottoni principali

### H.1.5 Edge (Windows)
- [ ] Stesso percorso di Chrome (Edge è Chromium, dovrebbe essere identico)
- [ ] Edge IE mode NON è supportato (verifica messaggio "use modern browser")

### H.1.6 Browser vecchi / non supportati
- [ ] IE11 → pagina "not supported" con link a browser moderni
- [ ] Chrome molto vecchio (>2 anni) → warning ma accesso consentito

### H.1.7 Accessibility smoke
- [ ] Navigazione da tastiera: Tab scorre elementi in ordine logico
- [ ] Skip link presente e funzionante
- [ ] Screen reader NVDA/VoiceOver legge label form corretti
- [ ] Contrast ratio ≥ 4.5:1 su testo normale
- [ ] Focus visibile su tutti gli elementi interattivi
- [ ] Form error associati ai campi via `aria-describedby`

### H.1.8 Responsive breakpoints
- [ ] 1920px (desktop large)
- [ ] 1440px (desktop standard)
- [ ] 1024px (laptop / iPad landscape)
- [ ] 768px (tablet portrait)
- [ ] 375px (iPhone)
- [ ] Nessun elemento tagliato o overflow in nessun breakpoint

---

## H.2 Linux agent

**OS test**: Ubuntu 22.04 LTS (primary), Debian 12, RHEL 9 / Rocky 9.

### H.2.1 Installation
- [ ] Download `sentrikat-agent-linux.sh` dalla UI
- [ ] Verifica che il download contenga il token dell'org corretta
- [ ] `sudo bash sentrikat-agent-linux.sh` → install riuscita
- [ ] `systemctl status sentrikat-agent` → active (running)
- [ ] `journalctl -u sentrikat-agent -f` → heartbeat ogni N minuti
- [ ] Binario installato in path atteso (`/usr/local/bin/sentrikat-agent` o simile)
- [ ] Config file `/etc/sentrikat/agent.conf` con permessi `600 root:root`
- [ ] Token NON leggibile da user non-root

### H.2.2 First scan
- [ ] Entro 5 min dall'install, agent invia primo inventory
- [ ] UI SaaS → asset appare con hostname correct
- [ ] Pacchetti installati rilevati (>50 per una Ubuntu fresh)
- [ ] CVE detected sul kernel / pacchetti noti
- [ ] Memoria RAM / CPU usage dell'agent < 50MB / < 1% idle

### H.2.3 Update & uninstall
- [ ] Trigger update dalla UI → agent si auto-aggiorna
- [ ] Verifica nuova versione in UI
- [ ] `sudo bash sentrikat-agent-linux.sh --uninstall` → rimuove tutto
- [ ] Nessun file residuo in `/etc/sentrikat` e `/usr/local/bin`
- [ ] Service unit rimossa da systemd

### H.2.4 Offline mode
- [ ] `iptables` blocca connettività all'API
- [ ] Agent retry con backoff (no crash, no flood di tentativi)
- [ ] Restore connettività → agent drain pending reports
- [ ] Nessuna perdita di dati

### H.2.5 Distro matrix
- [ ] Ubuntu 22.04 LTS ✅
- [ ] Ubuntu 20.04 LTS
- [ ] Debian 12
- [ ] RHEL 9 / Rocky 9 / AlmaLinux 9
- [ ] Amazon Linux 2023
- [ ] Docker container detection (se agent running in container → label correttamente)

---

## H.3 macOS agent

**OS test**: macOS 14 (Sonoma), macOS 13 (Ventura). ARM + Intel.

### H.3.1 Installation
- [ ] Download `sentrikat-agent-macos.sh`
- [ ] `sudo bash sentrikat-agent-macos.sh` → install OK
- [ ] Verifica LaunchDaemon in `/Library/LaunchDaemons/com.sentrikat.agent.plist`
- [ ] `sudo launchctl list | grep sentrikat` → running
- [ ] Binary su `/usr/local/bin/sentrikat-agent`
- [ ] Permessi `600 root:wheel` su config

### H.3.2 Gatekeeper / notarization
- [ ] Binary è firmato con Apple Developer ID
- [ ] Notarized (`spctl --assess` → accepted)
- [ ] Nessun warning Gatekeeper al primo run
- [ ] Se il binary NON è notarized → documenta come eccezione e
      istruzioni manuali per l'utente

### H.3.3 First scan
- [ ] Inventory invia: Homebrew packages, system info, kernel
- [ ] CVE detection su brew packages noti (es. openssl vecchio)
- [ ] Asset appare in UI con hostname `.local`
- [ ] `CPU % < 2%` idle

### H.3.4 Architecture support
- [ ] Intel Mac (x86_64)
- [ ] Apple Silicon (arm64)
- [ ] Binary universale o script che sceglie arch

### H.3.5 Uninstall
- [ ] `sudo bash sentrikat-agent-macos.sh --uninstall` pulisce tutto
- [ ] LaunchDaemon unloaded e rimosso
- [ ] Nessun processo residuo

---

## H.4 Windows agent

**OS test**: Windows 11, Windows Server 2022, Windows 10 (legacy).

### H.4.1 Installation
- [ ] Download `sentrikat-agent-windows.ps1` (o MSI)
- [ ] `powershell -ExecutionPolicy Bypass -File sentrikat-agent-windows.ps1`
      da admin prompt → install OK
- [ ] Windows service `SentriKatAgent` registrato
- [ ] `Get-Service SentriKatAgent` → Running
- [ ] Binary in `C:\Program Files\SentriKat\agent.exe`
- [ ] Config in `C:\ProgramData\SentriKat\agent.conf` con ACL ristretta

### H.4.2 First scan
- [ ] Inventory: packages WMI, Windows Update history, installed software
- [ ] CVE detection: Windows KB non patchati, software vulnerabili
- [ ] Asset appare in UI con hostname Windows corretto
- [ ] Event Log Windows: entry di agent senza errori

### H.4.3 Windows Defender / AV
- [ ] Defender NON segnala il binary come malware
- [ ] Binary firmato con certificato Authenticode valido
- [ ] SmartScreen non blocca l'esecuzione
- [ ] Se blocca → procedura per whitelist documentata

### H.4.4 Ping/heartbeat fix (Sprint 4)
- [ ] Agent invia heartbeat entro intervallo configurato
- [ ] UI mostra "Last seen" aggiornato (< 10 min)
- [ ] Test di networking: agent dietro proxy HTTP(S) con auth
- [ ] Test networking: agent dietro firewall corporate

### H.4.5 Update / Uninstall
- [ ] Agent auto-update da UI
- [ ] Uninstall via Control Panel Programs & Features (se MSI)
- [ ] Uninstall via script (`sentrikat-agent-windows.ps1 -Uninstall`)
- [ ] Nessun file residuo dopo uninstall

### H.4.6 Windows Server
- [ ] Install su Windows Server 2022 (Core + GUI)
- [ ] Server 2019 legacy
- [ ] Domain controller: agent non interferisce con AD services
- [ ] RDP session: UI admin panel funziona da RDP

---

## H.5 Agent → SaaS communication security

- [ ] Tutto il traffico su HTTPS (TLS 1.2+)
- [ ] Certificate pinning (se implementato) → resiste a MITM con cert
      self-signed
- [ ] Token agent in header `Authorization: Bearer <token>`, NON in query
- [ ] Payload firmato HMAC (se implementato)
- [ ] Revoca token: agent smette di funzionare entro 5 min
- [ ] Token NON è loggato né in server log né in agent log

---

## H.6 Checklist rapida (go/no-go)

**15 minuti:**

- [ ] Chrome: login + dashboard + aggiungi asset → OK
- [ ] Firefox: login + dashboard → OK
- [ ] Safari: login + dashboard → OK
- [ ] Linux agent: install + primo inventory visibile in UI
- [ ] Windows agent: install + primo inventory visibile in UI
- [ ] macOS agent: install + primo inventory visibile in UI

**Se tutti passano → browser/agent OK per go-live con i target supportati.**

**Agent fail su un OS**: documenta come "not supported at launch, coming soon"
nella marketing page se non è bloccante per il tuo target primario.
