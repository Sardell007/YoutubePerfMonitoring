from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
# from selenium.webdriver.common.desired_capabilities import DesiredCapabilities 
from selenium.webdriver.chrome.options import Options
from selenium.webdriver import ActionChains
from seleniumwire import webdriver
import time
import random
from scapy.all import *

from scapy.interfaces import IFACES
import socket
import re
import numpy as np
import json
import argparse
import csv

def vary_bandwidth(driver):
    bandwidth = random.randint(50 * 1024, 5 * 1024 * 1024)  # Random bandwidth between 50 kbps and 5 Mbps
    driver.set_network_conditions(
        offline=False,
        latency=0,
        download_throughput=bandwidth,
        upload_throughput=bandwidth
    )

def packet_filter(packet):
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load.decode(errors="ignore")
                if "videoplayback" in raw_data or "youtube.com" in raw_data:
                    return True
    return False

def save_dash_packet(packet):
    if packet_filter(packet):
        print(f"DASH Packet: {packet.summary()}")

def startPlayer(url, timeout, output_csv, output_log):
    options = Options()
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    driver = webdriver.Chrome(options=options)
    action = ActionChains(driver)
    start_time = time.time()
    driver.get(url)
    end_time = time.time()
    startup_time = end_time - start_time
    print("Start Up Delay:", startup_time)

    try:
        videoPlay = WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.XPATH, '//*[@class="ytp-play-button ytp-button"]')))
        if videoPlay.get_attribute("data-title-no-tooltip") == 'Play':
            videoPlay.click()
    except:
        print("Error from vidPlay")

    videoPlay = driver.find_element("xpath", '//*[@class="video-stream html5-main-video"]')
    action.context_click(videoPlay).perform()
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
    while time.time() - start_time < timeout:
        packets = sniff(prn=save_dash_packet, timeout=1)
        har_logs = driver.get_log("performance")
        all_har.append(har_logs)
        all_packets.append(packets)
        statStr = statsElem.text
        res = statStr.split("Optimal Res ")[-1].split(' / ')[0]
        speed = statStr.split("Connection Speed ")[-1].split('\n')[0]
        buffer_length = driver.execute_script("return document.querySelector('video').buffered.length > 0 ? "
                        "document.querySelector('video').buffered.end(0) - document.querySelector('video').currentTime : 0;")
        all_resolutions.append(res)
        all_speeds.append(speed)
        all_buffer_lengths.append(buffer_length)
        with open(output_csv, 'a', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow([time.time(), res, buffer_length])
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

    vid_duration = 10
    har_data, packets = startPlayer(url, vid_duration, output_csv, output_log)
    
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
