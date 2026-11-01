# Test-only FTPS server: user deploy/deploypass, TLS required on control and data.
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer

auth = DummyAuthorizer()
auth.add_user("deploy", "deploypass", "/data", perm="elradfmwMT")
TLS_FTPHandler.certfile, TLS_FTPHandler.keyfile = "/cert.pem", "/key.pem"
TLS_FTPHandler.tls_control_required = TLS_FTPHandler.tls_data_required = True
TLS_FTPHandler.authorizer = auth
TLS_FTPHandler.passive_ports = range(30000, 30010)
FTPServer(("0.0.0.0", 21), TLS_FTPHandler).serve_forever()
