from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    print(f"[Request] {flow.request.method} {flow.request.pretty_url}")
    print(f"Headers: {dict(flow.request.headers)}")
    if flow.request.content:
        print(f"Body: {flow.request.get_text()}")
    print("-" * 40)

def response(flow: http.HTTPFlow) -> None:
    print(f"[Response] {flow.request.method} {flow.request.pretty_url}")
    print(f"Status: {flow.response.status_code}")
    print(f"Headers: {dict(flow.response.headers)}")
    if flow.response.content:
        print(f"Body: {flow.response.get_text()}")
    print("=" * 40)
