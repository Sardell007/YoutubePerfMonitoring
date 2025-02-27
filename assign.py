from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver import ActionChains
from seleniumwire import webdriver
import time
import random
from scapy.all import *

import re
import numpy as np
import json
import argparse
import csv

def vary_bandwidth(driver):
    bandwidth = random.randint(50 * 1024, 5 * 1024 * 1024)  # Random bandwidth between 50 kbps and 5 Mbps
    print("Setting to: ", bandwidth)
    driver.set_network_conditions(
        offline=False,
        latency=0,
        download_throughput=bandwidth,
        upload_throughput=bandwidth
    )

# Since we can’t rely on packet payloads (encrypted), we should filter packets using: 
# ✅ Ports (80, 443 for HTTP/HTTPS; 443 for QUIC)
# ✅ YouTube’s Content Delivery Network (CDN) domains (googlevideo.com, youtube.com)
# ✅ QUIC-specific detection (UDP, port 443, and YouTube-related IPs)

# YouTube Data Flow
# When you watch a video, the process works like this:

# Your browser/app establishes a TCP connection with YouTube servers
# A TLS handshake occurs for encryption (when using HTTPS)
# HTTP requests are sent over this secure TCP connection
# YouTube servers respond by sending video data in chunks (segments)
# These segments are typically delivered using adaptive streaming protocols like DASH (Dynamic Adaptive Streaming over HTTP)

# Key Points About YouTube Traffic

# Modern YouTube traffic is almost exclusively encrypted via HTTPS
# For video delivery, YouTube uses content delivery networks (CDNs)
# The actual video data is typically streamed as segments requested via HTTP GET requests
# Multiple parallel TCP connections may be established to improve throughput
# YouTube uses adaptive bitrate streaming, adjusting quality based on network conditions

from scapy.all import *
import re

# YouTube-related domains (use external DNS resolution if needed)
# YOUTUBE_DOMAINS = ["youtube.com", "googlevideo.com", "youtu.be"]

# # YouTube video playback signatures in unencrypted HTTP (rare)
# VIDEO_STREAM_PATTERNS = re.compile(
#     r"(videoplayback|mime=video|range=\d+-\d+|clen=\d+|dur=\d+|ctier=|itag=)", re.IGNORECASE
# )

# # Common ports for YouTube video streaming
# YOUTUBE_PORTS = {80, 443, 8080}

# def packet_filter(packet):
#     if packet.haslayer(IP):
#         # Extract transport layer (TCP/UDP)
#         if packet.haslayer(TCP) or packet.haslayer(UDP):
#             port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            
#             # Filter by known ports (HTTP, HTTPS, QUIC)
#             if port in YOUTUBE_PORTS:
#                 return True
            
#         # Check raw data for unencrypted HTTP-based YouTube video streaming
#         if packet.haslayer(Raw):
#             raw_data = packet[Raw].load
#             try:
#                 decoded_data = raw_data.decode(errors="ignore")
#                 if VIDEO_STREAM_PATTERNS.search(decoded_data):
#                     return True
#             except UnicodeDecodeError:
#                 pass

#     return False

# def save_dash_packet(packet):
#     if packet_filter(packet):
#         pass

def startPlayer(url, timeout, output_csv, output_log, shaping):
    options = Options()
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    options.add_argument("--disable-blink-features=AutomationControlled")
    driver = webdriver.Chrome(options=options)
    action = ActionChains(driver)
    driver.get(url)
    start_time = time.time()
    videoPlay = WebDriverWait(driver, 7).until(EC.element_to_be_clickable((By.XPATH, '//*[@class="ytp-play-button ytp-button"]')))
    if videoPlay.get_attribute("data-title-no-tooltip") == 'Play':
        videoPlay.click()
    start_time = time.time()
    videoPlay = driver.find_element("xpath", '//*[@class="video-stream html5-main-video"]')    
    action.context_click(videoPlay).perform()
    is_playing = False
    while is_playing is False:
        is_playing = driver.execute_script("return document.querySelector('video').currentTime > 0")
    end_time = time.time()
    startup_time = end_time - start_time
    print("Start Up Delay:", startup_time)
    driver.execute_script('document.getElementsByClassName("ytp-menuitem")[6].click();');
    driver.execute_script('document.getElementsByClassName("ytp-contextmenu")[0].style.display = "none";');
    statsElem = driver.find_element("xpath", '//*[@class="html5-video-info-panel-content ytp-sfn-content"]')
    all_packets = []
    all_resolutions = []
    all_speeds = []
    all_har = []
    all_buffer_lengths = []
    print("Starting Sniff")
    start_time = time.time()
    #Concern:sniffing should begin before URL is requested? resolved: no, the metrics computed dont get affected by missing the initial packets
    while time.time() - start_time < timeout:
        packets = sniff(timeout=1)
        har_logs = driver.get_log("performance")
        all_har.append(har_logs)
        all_packets.append(packets)
        statStr = statsElem.text
        res = statStr.split("Optimal Res ")[-1].split(' / ')[0]
        speed = statStr.split("Connection Speed ")[-1].split('\n')[0]
        buffer_length = driver.execute_script("""
            let video = document.querySelector('video');
            return video.buffered.length > 0 ? video.buffered.end(0) - video.currentTime : 0;
        """)
        all_resolutions.append(res)
        all_speeds.append(speed)
        all_buffer_lengths.append(buffer_length)
        with open(output_csv, 'a', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow([time.time(), res, buffer_length])
        if shaping:
            vary_bandwidth(driver)
    print("End Sniff")
    driver.close()
    avg_resolution = np.mean([int(re.search(r'\d+', res).group()) for res in all_resolutions if re.search(r'\d+', res)])
    avg_bandwidth = np.mean([float(speed.split()[0]) for speed in all_speeds if speed.split()])
    variance_bandwidth = np.var([float(speed.split()[0]) for speed in all_speeds if speed.split()])
    rebuffering_ratio = sum(all_buffer_lengths) / timeout
    with open(output_log, 'w') as log_file:
        log_file.write(f"Video URL,{url}\n")
        log_file.write(f"Startup Time,{startup_time}\n")
        log_file.write(f"Re-buffering Ratio,{rebuffering_ratio}\n")
        log_file.write(f"Average Resolution,{avg_resolution}\n")
        log_file.write(f"Average Network Bandwidth,{avg_bandwidth}\n")
        log_file.write(f"Variance of Network Bandwidth,{variance_bandwidth}\n")
    return all_har, all_packets

def main(url, output_pref, shaping):
    output_pcap = f"{output_pref}.pcap"
    output_har = f"{output_pref}.har"
    output_csv = f"{output_pref}.csv"
    output_log = f"{output_pref}.log"
    vid_duration = 180
    har_data, packets = startPlayer(url, vid_duration, output_csv, output_log, shaping)
    all_packets = packets[0]
    for packet in packets[1:]:
        all_packets += packet
    wrpcap(output_pcap, all_packets)
    all_har = []
    for x in har_data:
        all_har += x
    with open(output_har, 'w') as har_file:
        har_file.write(json.dumps(all_har))
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="YouTube video URL")
    parser.add_argument("--output_pref", required=True, help="Output file prefix")
    parser.add_argument("--shaping", type=bool, default=False, help="Enable network shaping")
    args = parser.parse_args()
    main(args.url, args.output_pref, args.shaping)

#################################### TESTING

# from selenium import webdriver
# from selenium.webdriver.common.keys import Keys
# from selenium.webdriver.common.by import By
# from selenium.webdriver.support.ui import WebDriverWait
# from selenium.webdriver.support import expected_conditions as EC
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver import ActionChains
# from seleniumwire import webdriver
# import undetected_chromedriver as uc
# import time
# from scapy.all import *

# from scapy.interfaces import IFACES
# import numpy as np
# import argparse

# def startPlayer(url, timeout):
#     options = Options()
#     options.add_argument("--autoplay-policy=no-user-gesture-required")  # Allow autoplay
#     options.add_argument("--disable-blink-features=AutomationControlled")
#     driver = webdriver.Chrome(options=options)
#     # options = uc.ChromeOptions()
#     # options.binary_location = "C:\\Users\\SanyaKapoor\\Downloads\\chrome-win\\chrome-win\\chrome.exe"
#     # driver = uc.Chrome(options=options)
#     driver.get(url)
#     start_time = time.time()
#     while (time.time() - start_time) < timeout:
#         time.sleep(1)
#     driver.quit()
#     return

# def main(url, output_pref, shaping):
#     vid_duration = 180
#     startPlayer(url, vid_duration)
# if __name__ == "__main__":
#     parser = argparse.ArgumentParser()
#     parser.add_argument("--url", required=True, help="YouTube video URL")
#     parser.add_argument("--output_pref", required=True, help="Output file prefix")
#     parser.add_argument("--shaping", type=bool, default=False, help="Enable network shaping")
#     args = parser.parse_args()
#     main(args.url, args.output_pref, args.shaping)