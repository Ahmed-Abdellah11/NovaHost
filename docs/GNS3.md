# Deploying the AI DNS server in GNS3

Example addressing (change to yours): AI server `10.10.50.10/24` in the Data-Center VLAN, gateway `10.10.50.1`.

## 1. Build the image where the GNS3 server runs
```bash
unzip nova-classifier.zip && cd nova-classifier
docker build -t nova-ai-dns:1.0 .
```
(If you use the GNS3 VM, copy the folder into the VM and build there – GNS3 only sees images of its own Docker daemon.)

## 2. Create the node template
GNS3 → *Edit → Preferences → Docker containers → New* → **existing image** `nova-ai-dns:1.0`
* Name: `AI-DNS-Server`, adapters: 1
* **Start command:** `/entrypoint.sh`
* Environment: `UPSTREAM_DNS=8.8.8.8` and `NOVA_API_KEY=<your secret>`
* Network configuration (edit):
```
auto eth0
iface eth0 inet static
	address 10.10.50.10
	netmask 255.255.255.0
	gateway 10.10.50.1
```
Drag it into the Data-Center zone, connect to the L3 switch, and give the topology internet access with a **NAT node**
(the container needs it to reach `UPSTREAM_DNS`).

## 3. Make every VLAN use it (Cisco)
```
ip dhcp pool VLAN10
 network 10.10.10.0 255.255.255.0
 default-router 10.10.10.1
 dns-server 10.10.50.10
!
! users may ask ONLY the AI DNS server – no bypass with 8.8.8.8
ip access-list extended FORCE-NOVA-DNS
 permit udp any host 10.10.50.10 eq 53
 permit tcp any host 10.10.50.10 eq 53
 deny   udp any any eq 53 log
 deny   tcp any any eq 53 log
 deny   tcp any any eq 853 log
 permit ip any any
!
interface Vlan10
 ip access-group FORCE-NOVA-DNS in
```
Repeat for every user VLAN. Allow the admin VLAN to reach `10.10.50.10 tcp 8000` (dashboard). Browsers using
DNS-over-HTTPS bypass this – disable it in the browser/group policy.

## 4. Check
From a PC: `nslookup google.com` (works) → `nslookup paypal-secure-login-verify.xyz` twice (second answer `0.0.0.0`).
Open `http://10.10.50.10:8000` and watch the decisions appear. In the container: `docker logs` / GNS3 console shows
`[BLOCK] ...` and `[sync] ...` lines.
