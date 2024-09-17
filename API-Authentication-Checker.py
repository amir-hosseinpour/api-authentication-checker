from burp import IBurpExtender
from burp import IExtensionHelpers
from burp import IHttpRequestResponse
from burp import IRequestInfo
from burp import IResponseInfo
from burp import IScanIssue
import threading

class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # Set the extension name
        callbacks.setExtensionName("API-Authentication-Checker")
        self._callbacks.printOutput("Extension loaded successfully.")
        # Initialize a set to keep track of processed requests
        self._processed_requests = set()
        # Start the scanning process
        self.scan_proxy_history()

    def scan_proxy_history(self):
        try:
            self._callbacks.printOutput("Starting scan of proxy history...")
            # Fetch all items from proxy history
            proxy_history = self._callbacks.getProxyHistory()
            self._callbacks.printOutput("Found {} items in proxy history.".format(len(proxy_history)))
            for item in proxy_history:
                request = item.getRequest()
                request_info = self._helpers.analyzeRequest(item)
                url = request_info.getUrl()
                method = request_info.getMethod()
                path = url.getPath()
                # Create a unique key based on method and path
                request_key = (method, path)
                # Check if this request has already been processed
                if request_key in self._processed_requests:
                    self._callbacks.printOutput("Already processed {} {}".format(method, path))
                    continue
                else:
                    self._processed_requests.add(request_key)
                self._callbacks.printOutput("Processing URL: {}".format(url))
                if self.is_api_request(request_info):
                    self._callbacks.printOutput("Identified API request: {}".format(url))
                    # Remove authentication headers
                    new_headers = self.remove_auth_headers(request_info)
                    body = request[request_info.getBodyOffset():]
                    # Rebuild the request without authentication headers
                    new_request = self._helpers.buildHttpMessage(new_headers, body)
                    # Send the modified request
                    http_service = item.getHttpService()
                    new_request_response = self._callbacks.makeHttpRequest(
                        http_service, new_request
                    )
                    # Get the response bytes
                    response_bytes = new_request_response.getResponse()
                    if response_bytes:
                        response_info = self._helpers.analyzeResponse(response_bytes)
                        # Analyze the response
                        if self.is_response_successful(response_info):
                            self.report_issue(http_service, url, new_request_response)
                        else:
                            self._callbacks.printOutput("Access denied for URL: {}".format(url))
                    else:
                        self._callbacks.printOutput("No response received for URL: {}".format(url))
                else:
                    self._callbacks.printOutput("Skipping non-API request: {}".format(url))
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._callbacks.printError("An error occurred:")
            self._callbacks.printError(str(e))

    def is_api_request(self, request_info):
        url = request_info.getUrl()
        path_lower = url.getPath().lower()
        # Log the path being checked
        self._callbacks.printOutput("Checking if URL is API request: {}".format(path_lower))
        if ('/api/' in path_lower or
            '/v1/' in path_lower or
            '/v2/' in path_lower or
            '/v3/' in path_lower):
            return True
        headers = request_info.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:"):
                if "application/json" in header.lower():
                    return True
        return False

    def remove_auth_headers(self, request_info):
        headers = list(request_info.getHeaders())
        new_headers = []
        for header in headers:
            header_lower = header.lower()
            if not (header_lower.startswith('cookie:') or header_lower.startswith('authorization:')):
                new_headers.append(header)
            else:
                self._callbacks.printOutput("Removed header: {}".format(header))
        return new_headers

    def is_response_successful(self, response_info):
        status_code = response_info.getStatusCode()
        self._callbacks.printOutput("Response status code: {}".format(status_code))
        # Adjust the success criteria if needed
        return status_code == 200

    def report_issue(self, http_service, url, request_response):
        message = "Potential unauthenticated access at: {}".format(url)
        self._callbacks.printOutput(message)
        # Create a custom scan issue with the request and response
        issue = CustomScanIssue(
            http_service,
            url,
            "Unauthenticated API Access",
            "The API endpoint {} can be accessed without authentication. See the attached request and response.".format(url),
            "High",
            [request_response]  # Include the modified request and response
        )
        self._callbacks.addScanIssue(issue)

# Define a custom scan issue to display in Burp's Scanner tab
class CustomScanIssue(IScanIssue):

    def __init__(self, http_service, url, name, detail, severity, http_messages):
        self._http_service = http_service
        self._url = url
        self._name = name
        self._detail = detail
        self._severity = severity
        self._http_messages = http_messages

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0  # Custom issue type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service