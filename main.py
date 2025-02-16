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

from scapy.all import *

from scapy.interfaces import IFACES
import socket
import re
import numpy as np
import json
import argparse

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

def startPlayer(url, timeout):
    # desired_capabilities = DesiredCapabilities.CHROME
    # desired_capabilities["goog:loggingPrefs"] = {"performance": "ALL"}
    
    options = Options()
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    driver = webdriver.Chrome(options=options)
    action = ActionChains(driver)
    start_time = time.time()
    driver.get(url)
    end_time = time.time()
    print("Start Up Delay:", end_time - start_time)

    try:
        videoPlay = WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.XPATH, '//*[@class="ytp-play-button ytp-button"]')))
        if videoPlay.get_attribute("data-title-no-tooltip") == 'Play':
            videoPlay.click();
    except:
        print("Error from vidPlay")

    # driver.execute_script('document.getElementsByClassName("ytp-contextmenu")[0].style.display = "block";');
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

    print("Staring Sniff")
    start_time = time.time()
    while time.time() - start_time < timeout:
        packets = sniff(prn=save_dash_packet, timeout=1)
        har_logs = driver.get_log("performance") 
        # har_logs = driver.har
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
    print("End Sniff")


    driver.close()
    return all_har, all_packets, all_resolutions, all_speeds, all_buffer_lengths

def main(url, output_pref, shaping):
    output_pcap = f"{output_pref}.pcap"
    output_har = f"{output_pref}.har"
    # output_csv = f"{output_pref}.csv"
    # output_log = f"{output_pref}.log"

    vid_duration = 10
    har_data, packets, resolutions, network_speeds, buffer_lengths = startPlayer(url, vid_duration)
    
    print("Resolutions", resolutions)
    print("Network Speed", network_speeds)
    print("Buffer Lengths", buffer_lengths)
    
    all_packets = packets[0]
    for packet in packets[1:]:
        all_packets+=packet
    
    wrpcap(output_pcap, all_packets)
    
    all_har = []
    for x in har_data:
        all_har+=x
    
    with open(output_har, 'w') as har_file:
        har_file.write(har_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="YouTube video URL")
    parser.add_argument("--output_pref", required=True, help="Output file prefix")
    parser.add_argument("--shaping", type=bool, default=False, help="Enable network shaping")
    args = parser.parse_args()
    main(args.url, args.output_pref, args.shaping)