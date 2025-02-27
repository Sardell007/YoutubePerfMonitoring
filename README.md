# Overview of Script:

libraries, how tasks are accomplished

# Design Decisions:

1. Various sources define "start up latency" differently:
- Some sugest it is from the time a video is requested (eg. clicking a URL)
- Others suggest that it is the difference between clicking play and the time it takes for first frame to render
For this assignment, we consider the second one - we calculate the time elapsed between playing click on the video and the time when it actually plays

2. Pcap Filtering:
Pcap filtering via scripting requires more than a seconds time to complete, atleast by the methods we were using (port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport). And there appeared to be no concrete method other than filtering out 443 and 80 traffic. So we decided to do it later

3. Traffic Controlling:
driver.set_network_conditions(
        offline=False,
        latency=0,
        download_throughput=bandwidth,
        upload_throughput=bandwidth
    )
After trying the free tools like netlimiter, we came across this broswer option whoch was the most convenient

# Challenges:

1. One of teh biggest challenges to overcome was bot detection for us, in this time we tried the following strategies:
Differemt Browser versions
Edge, firefox
Undetectable Chrome
VPN
Hardcoding certain flags

Nothing worked, on opening another tab on te testing window chrome even showed bot behavior is detected

After a lot of trying, we came across the     
options.add_argument("--disable-blink-features=AutomationControlled")
Flag, this allows you to have behaviour as suspicious as possible but hrome will not block you because it knows you ate legit

2. Collecting data every second was also a challenge - 

# Part 3 Questions:
* ytm -> youtube upsteam request
* every itag is 18
* i/o graph shows bursts of data
*  quic data is avaialbke
