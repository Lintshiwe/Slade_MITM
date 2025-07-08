# MITM Proxy (Educational)

This project is a simple Man-in-the-Middle (MITM) proxy using Python and the mitmproxy library. It can intercept and log HTTP/HTTPS traffic for educational purposes only.

## Requirements

- Python 3.7+
- mitmproxy (already installed)

## Usage

1. Run the proxy (terminal):

   ```powershell
   c:/Users/ntoam/Desktop/MIT/.venv/Scripts/mitmproxy.exe -s mitm_script.py --listen-port 8888
   ```

   Or launch the GUI:

   ```powershell
   c:/Users/ntoam/Desktop/MIT/.venv/Scripts/python.exe mitm_gui.py
   ```

2. Configure your browser or device to use `localhost:8080` as the HTTP/HTTPS proxy.

3. Visit any website. Requests and responses will be logged.

4. To stop the proxy, press `Ctrl+C` in the terminal.

## Notes

- For HTTPS interception, you may need to install mitmproxy's CA certificate in your browser. mitmproxy will provide instructions when you visit an HTTPS site.
- Use this tool only in environments where you have permission to intercept traffic.

## Educational Purpose Only

This tool is for learning and testing. Do not use it for unauthorized interception.
