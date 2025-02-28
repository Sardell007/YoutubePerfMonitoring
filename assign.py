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
    all_csv_rows = []
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
        all_csv_rows.append([time.time(), res, buffer_length])
        if shaping:
            vary_bandwidth(driver)
    print("End Sniff")
    driver.close()
    
    with open(output_csv, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        for data in all_csv_rows:
            csv_writer.writerow(data)
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
