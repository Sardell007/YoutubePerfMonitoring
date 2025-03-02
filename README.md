# Overview of Script:

The code collects data through multiple methods simultaneously. It captures network packets using Scapy's sniff function to record all network traffic. It extracts browser performance logs using Selenium's get_log("performance") to obtain HAR (HTTP Archive) data. The code also scrapes video statistics directly from YouTube's stats panel, recording resolution and connection speed. Additionally, it uses JavaScript execution to measure buffer length by calculating the difference between the buffered end time and current playback time. All this data is collected at regular intervals while the video plays and is saved to various output files (CSV, log, PCAP, and HAR) for later analysis of streaming performance.

# Design Decisions:

Various sources define "start-up latency" differently:
Some suggest it is the time from when a video is requested (e.g., clicking a URL). Others suggest it is the difference between clicking "play" and the time it takes for the first frame to render. For this assignment, we consider the second definition—we calculate the time elapsed between clicking play on the video and the time when it actually starts playing
PCAP Filtering: PCAP filtering via scripting requires more than a second to complete, at least using the methods we were trying (e.g., port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport). Since there appeared to be no concrete method other than filtering out traffic on ports 443 and 80, we decided to perform the filtering manually rather than via script.
Traffic Controlling: After trying free tools like NetLimiter, we discovered a more convenient browser option:
Copydriver.set_network_conditions(
    offline=False, 
    latency=0, 
    download_throughput=bandwidth, 
    upload_throughput=bandwidth
)

# Challenges:

One of the biggest challenges for us to overcome was bot detection. During our testing period, we tried the following strategies:

Different browser versions (Edge, Firefox)
Undetectable Chrome
VPN
Hardcoding certain flags

Nothing worked. When opening another tab in the testing window, Chrome even showed a message that bot behavior was detected.
After numerous attempts, we discovered the options.add_argument("--disable-blink-features=AutomationControlled") flag. This allows you to have behavior that would normally be flagged as suspicious, but Chrome will not block you because it recognizes you as legitimate.

Collecting data every second was also a challenge. The main while loop was taking more than a second to complete each iteration, which meant we weren't able to collect data points at precisely one-second intervals. We optimized the loop by removing PCAP filtering and other resource-intensive operations, which improved performance. Despite these optimizations, we noticed that for some files, the program was only collecting approximately 175 rows of data instead of the expected 180 rows (for a 3-minute video). This discrepancy suggests that even with our optimizations, some iterations of the loop were still taking slightly longer than one second to complete, resulting in fewer total data points than the video duration would suggest. This timing inconsistency affects the granularity of our metrics and requires consideration when analyzing the results.

# Part 3 Questions:

The Video Width and Height CDFs show resolution distribution patterns, with common resolutions creating noticeable steps in the graphs - most videos having widths between 300-850 pixels and heights between 180-480 pixels, with significant jumps at standard resolution breakpoints.

The Video FPS CDF shows that most frames-per-second values cluster between 24-30 fps, with notable jumps at 24, 25, and 30 fps indicating common video frame rates. The Buffer CDF reveals a relatively consistent increase in buffer length distribution up to about 80 seconds, followed by a sharp rise. 

The Start Up Delay CDF indicates most videos begin playing within 0.4-0.8 seconds, with few videos taking longer than 1 second to start. The Network Bandwidth CDF shows bandwidth distribution predominantly between 0-6000 units (kbps), with most sessions experiencing less than 4000 units.

Findings from PCAP & HAR files:

In our analysis of the YouTube traffic data, we identified the itag value "18" and MIME type "video/mp4" within the request URL parameters (specifically in "itag=18" and "mime=video%2Fmp4"). This specific combination is significant because itag 18 represents a 360p resolution video with combined audio and video streams in MP4 format. This means the client requested a medium-quality, standard definition video in a widely compatible format rather than requesting separate audio and video streams which would be indicated by different itag values (such as 137 for 1080p video-only or 140 for audio-only). By recognizing these parameters in the URL request to "googlevideo.com", we can definitively identify not just that this is YouTube content, but specifically what quality and format of media was being requested by the client. (Source: YouTube video stream format codes itags)

"message": 1.3\",\"sanList\":[\"*.c.mail.googleusercontent.com\",\"rr2---sn-q4fl6nss.googlevideo.com\",\"*.a1.googlevideo.com\",\"*.c.youtube.com\",\"*.gvt1.com\",\"*.gcpcdn.gvt1.com\",\"*.c.googlesyndication.com\",\"xn--ngstr-lra8j.[TRUNCATED]ip=62.20.16.37&id=o-AFI96jc09yDa187fO7n3U7LLX3YGKJBP6tHCepgm7AjEV&itag=18&source=youtube&requiressl=yes&mh=X6&mm=156%2C41688%2C71259&mn=UbQEr%2Cvqt7U%2C7mX4B&ms=UbQEr%2Cvqt7U%2C7mX4B&mv=3&mvi=2&pl=09&ctier=L&initcwndbps=7170739&siu=2&spc=4NNAI-ZKdBM6KNH9z2Z4_zHyfZ3rhnzPGCkj5YX63WoO&vprv=2&svpuc=2&mime=video%2Fmp

The following are indicators we consolidated to identify youtube data in HAR files:

Request URL Domain: rr2---sn-q4fl6nss.googlevideo.com
This is a Google Video CDN server that hosts YouTube content.
MIME Type Parameter: mime=video%2Fmp4
This clearly indicates this is a video stream request (URL-encoded as video/mp4).
Itag Parameter: itag=18
Each itag value corresponds to a specific video/audio format and quality. Itag 18 typically represents a 360p video with audio combined.
Content Identifiers:
source=youtube
id=o-AFlH1SFiDRVJvzUE4wO8Yr1zfdJxPUB27p1BMWJAMAwws
Format Indicators:
ratebypass=yes
dur=61720649 (duration in milliseconds)
Response Headers:
YouTube-specific headers like:
X-Bandwidth-Est
X-Response-Itag

We were only able to identify itag 18 in our HAR data even though from our CSVs we notice different resolutions.

Within the packet logs, HTTP transactions can be isolated by tracking complete TCP/QUIC streams from initial request to final response packet, calculating durations using packet timestamps and sizes by summing payload bytes across all packets in each stream.

Considering Only UDP Packets:
As we found out Youtube uses QUIC protocol for transfer of video/audio data, we consider only UDP packets which are transferred. Ideally we would consider only packets with QUIC protocol, but identifying these packets was found to be difficult. We were able to distinguish QUIC protocol packets with other UDP packets using wireshark, but using python scapy which provides tools to read pcap using python was not able to distinguish.
