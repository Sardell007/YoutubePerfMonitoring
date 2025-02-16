import argparse
import time
import os
import json
import csv
import subprocess
import pyshark
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from browsermobproxy import Server

# Set your BrowserMob Proxy path
BROWSERMOB_PROXY_PATH = "C:\\Users\\SanyaKapoor\\Downloads\\browsermob-proxy-2.1.4-bin\\browsermob-proxy-2.1.4\\bin\\browsermob-proxy"

def setup_browsermob_proxy():
    """Start BrowserMob Proxy for capturing HAR files."""
    server = Server(BROWSERMOB_PROXY_PATH)
    server.start()
    proxy = server.create_proxy()
    return server, proxy

def start_packet_capture(output_pcap):
    """Start packet capture using tshark."""
    capture_process = subprocess.Popen(["tshark", "-w", output_pcap])
    return capture_process

def setup_selenium(proxy, chromium_path):
    """Configure Selenium WebDriver with Chromium and Proxy."""
    chrome_options = Options()
    chrome_options.binary_location = chromium_path
    #chrome_options.add_argument("--headless=new")  # Run in headless mode (remove if debugging)
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-popup-blocking")
    chrome_options.add_argument(f"--proxy-server={proxy.proxy}")
    chrome_options.add_argument("--no-sandbox")  # <--- Add this line
    chrome_options.add_argument("--disable-dev-shm-usage")  # Helps in some cases
    chrome_options.add_argument("--ignore-certificate-errors")
    # chrome_options.add_argument("--disable-features=NetworkService")  
    chrome_options.add_argument("--enable-unsafe-swiftshader")  
    service = Service("C:\\Users\\SanyaKapoor\\Downloads\\chromedriver-win64\\chromedriver-win64\\chromedriver.exe")  # Ensure chromedriver.exe is in the script directory
    driver = webdriver.Chrome(service=service, options=chrome_options)

    return driver

def get_video_metrics(driver):
    time.sleep(5)  # Add delay to let YouTube load
    """Extract video resolution, buffer occupancy, and startup latency."""
    script = """
    var player = document.querySelector('video');
    return {
        resolution: player.videoWidth + 'x' + player.videoHeight,
        buffer: player.buffered.length > 0 ? player.buffered.end(0) - player.currentTime : 0
    };
    """
    return driver.execute_script(script)

def skip_ads(driver):
    """Attempts to skip YouTube ads if detected."""
    try:
        skip_button = WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.CLASS_NAME, "ytp-ad-skip-button"))
        )
        skip_button.click()
        print("[INFO] Skipped ad")
    except:
        print("[INFO] No skippable ad detected")

def save_data(output_csv, metrics_data):
    """Save video performance metrics to a CSV file."""
    with open(output_csv, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Resolution", "Buffer Occupancy"])
        writer.writerows(metrics_data)

def save_har_file(proxy, output_har):
    """Save HAR data from BrowserMob Proxy."""
    har_data = proxy.har
    with open(output_har, "w") as file:
        json.dump(har_data, file, indent=4)

def analyze_pcap(output_pcap):
    """Extract bandwidth statistics from PCAP."""
    capture = pyshark.FileCapture(output_pcap, display_filter="tcp")
    bandwidths = []
    for packet in capture:
        if hasattr(packet, 'length'):
            bandwidths.append(int(packet.length))
    
    avg_bandwidth = sum(bandwidths) / len(bandwidths) if bandwidths else -1
    variance_bandwidth = sum((x - avg_bandwidth) ** 2 for x in bandwidths) / len(bandwidths) if bandwidths else -1
    return avg_bandwidth, variance_bandwidth

def save_log(output_log, url, startup_time, rebuffering_ratio, avg_resolution, avg_bandwidth, variance_bandwidth):
    """Save session data to a log file."""
    with open(output_log, "w") as file:
        file.write(f"Video URL,Startup Time,Re-buffering Ratio,Average Resolution,Average Network Bandwidth,Variance of Network Bandwidth\n")
        file.write(f"{url},{startup_time},{rebuffering_ratio},{avg_resolution},{avg_bandwidth},{variance_bandwidth}\n")

def main(url, output_pref, shaping):
    output_pcap = f"{output_pref}.pcap"
    output_har = f"{output_pref}.har"
    output_csv = f"{output_pref}.csv"
    output_log = f"{output_pref}.log"

    server, proxy = setup_browsermob_proxy()
    proxy.new_har("youtube_session")

    pcap_process = start_packet_capture(output_pcap)
    driver = setup_selenium(proxy, "C:\\Users\\SanyaKapoor\\Downloads\\chrome-win\\chrome-win\\chrome.exe")

    print("[INFO] Opening YouTube...")
    driver.get(url)
    time.sleep(2)

    print("[INFO] Playing video...")
    skip_ads(driver)
    
    metrics_data = []
    start_time = time.time()
    
    for _ in range(180):  # 3 minutes = 180 seconds
        metrics = get_video_metrics(driver)
        timestamp = time.time() - start_time
        metrics_data.append([timestamp, metrics["resolution"], metrics["buffer"]])
        time.sleep(1)

    driver.quit()
    pcap_process.terminate()

    save_data(output_csv, metrics_data)
    save_har_file(proxy, output_har)
    avg_bandwidth, variance_bandwidth = analyze_pcap(output_pcap)
    avg_resolution = sum([int(x[1].split("x")[0]) for x in metrics_data]) / len(metrics_data)
    rebuffering_ratio = sum([x[2] for x in metrics_data]) / len(metrics_data)

    save_log(output_log, url, 1, rebuffering_ratio, avg_resolution, avg_bandwidth if shaping else -1, variance_bandwidth if shaping else -1)

    proxy.close()
    server.stop()
    print("[INFO] Data collection complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="YouTube video URL")
    parser.add_argument("--output_pref", required=True, help="Output file prefix")
    parser.add_argument("--shaping", type=bool, default=False, help="Enable network shaping")
    args = parser.parse_args()
    main(args.url, args.output_pref, args.shaping)
