from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import JPanel, JButton, JTextField, JTextArea, JScrollPane, JLabel, JFileChooser, JCheckBox, JMenuItem
import java.awt.BorderLayout as BorderLayout
from java.io import PrintWriter
from java.net import URL
import threading
import random
import string

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HeaderPWN Burp")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        
        # UI Setup
        self.panel = JPanel(BorderLayout())
        controls = JPanel()
        self.url_field = JTextField("https://example.com", 25)
        self.status_code_field = JTextField("200", 4)
        self.random_ua_check = JCheckBox("Random UA")
        self.btn_load_headers = JButton("Load Headers File", actionPerformed=self.load_headers_action)
        self.btn_run = JButton("Run Fuzzer", actionPerformed=self.run_fuzzer)
        
        controls.add(JLabel("Target URL: "))
        controls.add(self.url_field)
        controls.add(JLabel("Status Code:"))
        controls.add(self.status_code_field)
        controls.add(self.random_ua_check)
        controls.add(self.btn_load_headers)
        controls.add(self.btn_run)
        
        self.log_area = JTextArea(25, 80)
        self.log_area.setEditable(False)
        self.panel.add(controls, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.log_area), BorderLayout.CENTER)
        
        # State variables
        self.headers_list = []
        self.preserved_cookies = ""
        self.user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"]
        
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        self._stdout.println("HeaderFuzz Loaded: Right-click any request to 'Send to HeaderFuzz'")

    # --- Context Menu Implementation ---
    def createMenuItems(self, invocation):
        self.context_invocation = invocation
        menu_list = []
        menu_item = JMenuItem("Send to HeaderFuzz", actionPerformed=self.context_menu_action)
        menu_list.append(menu_item)
        return menu_list

    def context_menu_action(self, event):
        # Get the selected request
        selected_messages = self.context_invocation.getSelectedMessages()
        if not selected_messages:
            return
        
        request_info = self._helpers.analyzeRequest(selected_messages[0])
        headers = list(request_info.getHeaders())
        
        # Update UI with the target URL
        self.url_field.setText(str(request_info.getUrl()))
        
        # Extract and preserve the Cookie header
        self.preserved_cookies = ""
        for h in headers:
            if h.lower().startswith("cookie:"):
                self.preserved_cookies = h
                break
        
        self.log_area.append("[!] Captured request. Cookies preserved: %s\n" % ("Yes" if self.preserved_cookies else "None found"))

    # --- Core Logic ---
    def load_headers_action(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            with open(file_path, 'r') as f:
                self.headers_list = [line.strip() for line in f if line.strip()]
            self._stdout.println("Loaded %d headers" % len(self.headers_list))

    def make_request(self, target_url, header_str):
        cb = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
        full_url = target_url + ("&" if "?" in target_url else "?") + "cachebuster=" + cb
        java_url = URL(full_url)
        
        port = java_url.getPort() if java_url.getPort() != -1 else (443 if java_url.getProtocol() == "https" else 80)
        http_service = self._helpers.buildHttpService(java_url.getHost(), port, java_url.getProtocol() == "https")
        
        # Build headers for the fuzzed request
        headers = ["GET %s HTTP/1.1" % (java_url.getPath() + "?" + (java_url.getQuery() or "")),
                   "Host: %s" % java_url.getHost(),
                   "Connection: close"]
        
        # Inject preserved cookies
        if self.preserved_cookies:
            headers.append(self.preserved_cookies)
            
        # Add the fuzzed header
        if ": " in header_str:
            headers.append(header_str)
            
        # Handle User-Agent
        ua = random.choice(self.user_agents) if self.random_ua_check.isSelected() else "Mozilla/5.0"
        headers.append("User-Agent: %s" % ua)

        request_bytes = self._helpers.buildResendableRequest(headers, None)
        return self._callbacks.makeHttpRequest(http_service, request_bytes)

    def fuzz_logic(self):
        target_url = self.url_field.getText()
        target_status = int(self.status_code_field.getText())
        self.log_area.append("--- Starting Scan on %s ---\n" % target_url)
        
        for header in self.headers_list:
            resp_res = self.make_request(target_url, header)
            if resp_res and resp_res.getResponse():
                resp_info = self._helpers.analyzeResponse(resp_res.getResponse())
                if resp_info.getStatusCode() == target_status:
                    length = len(resp_res.getResponse()) - resp_info.getBodyOffset()
                    self.log_area.append("[Status: %d] [Len: %d] Header: %s\n" % (resp_info.getStatusCode(), length, header))
        
        self.log_area.append("--- Scan Complete ---\n")

    def run_fuzzer(self, event):
        if not self.headers_list:
            self.log_area.append("Error: Load a headers file first!\n")
            return
        threading.Thread(target=self.fuzz_logic).start()

    def getTabCaption(self): return "HeaderFuzz"
    def getUiComponent(self): return self.panel
