from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver import ActionChains
from seleniumwire import webdriver
import time
import csv
from datetime import datetime
import statistics
import random
import win32com.client
import pythoncom
import sys
from scapy.all import *
import socket
import re
import numpy as np
import json
import argparse

class YouTubeAnalyzer:
    def __init__(self, url, output_pref, shaping=False):
        self.url = url
        self.output_pref = output_pref
        self.shaping = shaping
        self.nl = None
        self.filter = None
        self.driver = None
        
    def init_netlimiter(self):

        """Initialize NetLimiter COM interface"""
        try:
            pythoncom.CoInitialize()
            nl = win32com.client.Dispatch("NetLimiter.API")
            version = nl.Version
            print(f"Connected to NetLimiter version: {version}")
            return nl
        except Exception as e:
            print(f"Failed to initialize NetLimiter: {str(e)}")
            print("Please ensure NetLimiter is installed and running with admin privileges")
            return None

    def setup_chrome_filter(self):
        """Set up NetLimiter filter for Chrome"""
        try:
            filters = self.nl.Filters
            # Remove existing filter if it exists
            for filter in filters:
                if filter.Name == "ChromeLimit":
                    filter.Remove()
            
            # Create new filter
            filter = self.nl.CreateFilter()
            filter.Name = "ChromeLimit"
            filter.PathNamePattern = "chrome.exe"
            filter.Apply()
            return filter
        except Exception as e:
            print(f"Failed to setup Chrome filter: {str(e)}")
            return None

    def modify_bandwidth(self):
        """Modify network bandwidth using NetLimiter"""
        try:
            bandwidth_kbps = random.uniform(50, 5000)
            bandwidth_bps = int(bandwidth_kbps * 1024)
            
            # Remove existing rules
            for rule in self.filter.Rules:
                rule.Remove()
            
            # Add new rule
            rule = self.filter.Rules.Add()
            rule.LimitIn = bandwidth_bps
            rule.LimitOut = bandwidth_bps
            rule.Apply()
            
            print(f"Set bandwidth limit to {bandwidth_kbps:.2f} kbps")
            return bandwidth_kbps
        except Exception as e:
            print(f"Failed to modify bandwidth: {str(e)}")
            return 0

    def setup_browser(self):
        """Initialize and setup Chrome browser"""
        options = Options()
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        self.driver = webdriver.Chrome(options=options)
        return self.driver

    def packet_filter(self, packet):
        """Filter for YouTube packets"""
        if packet.haslayer(IP):
            if packet.haslayer(TCP):
                if packet.haslayer(Raw):
                    try:
                        raw_data = packet[Raw].load.decode(errors="ignore")
                        return "videoplayback" in raw_data or "youtube.com" in raw_data
                    except:
                        return False
        return False

    def collect_metrics(self, timeout=10):
        """Collect all metrics from YouTube playback"""
        action = ActionChains(self.driver)
        
        # Load video and measure startup time
        start_time = time.time()
        self.driver.get(self.url)
        startup_time = time.time() - start_time
        print(f"Startup delay: {startup_time:.2f} seconds")

        # Handle video player setup
        try:
            video_play = WebDriverWait(self.driver, 20).until(
                EC.element_to_be_clickable((By.XPATH, '//*[@class="ytp-play-button ytp-button"]')))
            if video_play.get_attribute("data-title-no-tooltip") == 'Play':
                video_play.click()

            # Open stats panel
            video_element = self.driver.find_element("xpath", '//*[@class="video-stream html5-main-video"]')
            action.context_click(video_element).perform()
            self.driver.execute_script('document.getElementsByClassName("ytp-menuitem")[6].click();')
            stats_elem = self.driver.find_element("xpath", '//*[@class="html5-video-info-panel-content ytp-sfn-content"]')
        except Exception as e:
            print(f"Error setting up video player: {str(e)}")
            return None

        # Initialize data collection lists
        all_packets = []
        metrics_data = []
        
        # Main collection loop
        print("Starting metrics collection...")
        collection_start = time.time()
        while time.time() - collection_start < timeout:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Modify bandwidth if shaping is enabled
            current_bandwidth = self.modify_bandwidth() if self.shaping else 0
            
            # Collect network packets
            packets = sniff(prn=lambda x: x if self.packet_filter(x) else None, 
                          timeout=1, 
                          store=1)
            all_packets.extend([p for p in packets if p is not None])
            
            # Collect player stats
            try:
                stats_text = stats_elem.text
                resolution = stats_text.split("Optimal Res ")[-1].split(' / ')[0]
                speed = stats_text.split("Connection Speed ")[-1].split('\n')[0]
                buffer_length = self.driver.execute_script(
                    "return document.querySelector('video').buffered.length > 0 ? "
                    "document.querySelector('video').buffered.end(0) - "
                    "document.querySelector('video').currentTime : 0;"
                )
                
                metrics_data.append({
                    'timestamp': current_time,
                    'resolution': resolution,
                    'speed': speed,
                    'buffer_length': buffer_length,
                    'bandwidth_limit': current_bandwidth
                })
                
            except Exception as e:
                print(f"Error collecting metrics: {str(e)}")
            
            time.sleep(1)

        return all_packets, metrics_data, startup_time

    def save_results(self, packets, metrics_data, startup_time):
        """Save all collected data to files"""
        # Save PCAP
        wrpcap(f"{self.output_pref}.pcap", packets)
        
        # Extract and calculate final metrics
        resolutions = [m['resolution'] for m in metrics_data]
        speeds = [m['speed'] for m in metrics_data]
        buffer_lengths = [m['buffer_length'] for m in metrics_data]
        
        # Calculate aggregate metrics
        try:
            avg_resolution = statistics.mean([int(res.split('p')[0]) for res in resolutions if res.endswith('p')])
            speed_values = [float(speed.split(' ')[0]) for speed in speeds if speed.split(' ')[0].replace('.', '').isdigit()]
            avg_bandwidth = statistics.mean(speed_values) if speed_values else 0
            bandwidth_variance = statistics.variance(speed_values) if len(speed_values) > 1 else 0
            rebuffer_ratio = (sum(1 for b in buffer_lengths if b <= 0.5) / len(buffer_lengths)) * 100
        except Exception as e:
            print(f"Error calculating metrics: {str(e)}")
            return

        # Save CSV
        with open(f"{self.output_pref}.csv", 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Timestamp', 'Resolution', 'Buffer Occupancy', 'Bandwidth Limit'])
            for metric in metrics_data:
                writer.writerow([
                    metric['timestamp'],
                    metric['resolution'],
                    metric['buffer_length'],
                    metric['bandwidth_limit']
                ])

        # Save LOG
        with open(f"{self.output_pref}.log", 'w') as logfile:
            log_data = [
                self.url,
                f"{startup_time:.2f}",
                f"{rebuffer_ratio:.2f}",
                f"{avg_resolution:.2f}",
                f"{avg_bandwidth:.2f}",
                f"{bandwidth_variance:.2f}"
            ]
            logfile.write(','.join(map(str, log_data)))

    def cleanup(self):
        """Clean up resources"""
        if self.driver:
            self.driver.quit()
        
        if self.filter:
            try:
                for rule in self.filter.Rules:
                    rule.Remove()
                self.filter.Remove()
            except:
                pass
            
        if self.nl:
            try:
                pythoncom.CoUninitialize()
            except:
                pass

    def run(self):
        """Main execution method"""
        try:
            # Initialize NetLimiter if shaping is enabled
            if self.shaping:
                self.nl = self.init_netlimiter()
                if not self.nl:
                    print("Failed to initialize NetLimiter")
                    return
                
                self.filter = self.setup_chrome_filter()
                if not self.filter:
                    print("Failed to setup Chrome filter")
                    return

            # Setup browser and collect metrics
            self.setup_browser()
            packets, metrics_data, startup_time = self.collect_metrics()
            
            # Save results
            if packets and metrics_data:
                self.save_results(packets, metrics_data, startup_time)
                print(f"Analysis complete. Results saved with prefix: {self.output_pref}")
            else:
                print("No data collected")

        except Exception as e:
            print(f"Error during execution: {str(e)}")
        
        finally:
            self.cleanup()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="YouTube video URL")
    parser.add_argument("--output_pref", required=True, help="Output file prefix")
    parser.add_argument("--shaping", type=bool, default=False, help="Enable network shaping")
    args = parser.parse_args()

    analyzer = YouTubeAnalyzer(args.url, args.output_pref, args.shaping)
    analyzer.run()

if __name__ == "__main__":
    main()