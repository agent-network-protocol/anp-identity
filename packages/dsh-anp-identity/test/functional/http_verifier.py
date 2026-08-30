"""Independent HTTPS fixture backed by the ANP Python verifier."""

import argparse
import json
import ssl
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from anp.authentication import verify_http_message_signature


class VerifierHandler(BaseHTTPRequestHandler):
    """Verify the exact request received by the HTTPS server."""

    server_version = "ANPFunctionalVerifier/1"

    def do_GET(self) -> None:  # pylint: disable=invalid-name
        self._verify_and_respond()

    def do_POST(self) -> None:  # pylint: disable=invalid-name
        self._verify_and_respond()

    def log_message(self, format_: str, *args: Any) -> None:
        del format_, args

    def _verify_and_respond(self) -> None:
        content_length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(content_length)
        document_path = self.server.document_path  # type: ignore[attr-defined]
        try:
            did_document = json.loads(document_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            self._json_response(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"verified": False, "reason": "DID document unavailable"},
            )
            return

        host = self.headers.get("host")
        if host is None:
            self._json_response(
                HTTPStatus.BAD_REQUEST,
                {"verified": False, "reason": "Host header unavailable"},
            )
            return
        request_url = f"https://{host}{self.path}"
        verified, reason, metadata = verify_http_message_signature(
            did_document=did_document,
            request_method=self.command,
            request_url=request_url,
            headers=dict(self.headers.items()),
            body=body if content_length > 0 else None,
        )
        status = HTTPStatus.OK if verified else HTTPStatus.UNAUTHORIZED
        self._json_response(
            status,
            {
                "verified": verified,
                "reason": reason,
                "method": self.command,
                "path": self.path,
                "keyid": metadata.get("keyid"),
                "contentDigestPresent": self.headers.get("content-digest") is not None,
            },
        )

    def _json_response(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--document", required=True, type=Path)
    parser.add_argument("--ready-file", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 0), VerifierHandler)
    server.document_path = args.document  # type: ignore[attr-defined]
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(args.certificate, args.private_key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    args.ready_file.write_text(
        json.dumps({"origin": f"https://localhost:{port}"}),
        encoding="utf-8",
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
