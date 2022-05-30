from subprocess import Popen, PIPE

def server(args=""):
    proc = Popen(f"python3 server.py {args}", stdout=PIPE, shell=True)
    return proc.stdout.read().decode("utf-8")

def client(args=""):
    proc = Popen(f"python3 client.py {args}", stdout=PIPE, shell=True)
    return proc.stdout.read().decode("utf-8")

def test_server():
    assert "ERROR - Usage: python3 server.py <port>" in server("")
    assert "ERROR - Usage: python3 server.py <port>" in server("8040 -d")
    assert "ERROR - Port must be a number" in server("abc")
    assert "ERROR - Port must be between 1024 and 65535" in server("999")
    assert "ERROR - Port must be between 1024 and 65535" in server("69746")

def test_client():
    assert "ERROR - Usage: python3 client.py <client_id> <port> [host]" in client("")
    assert "ERROR - Usage: python3 client.py <client_id> <port> [host]" in client("qwe")
    assert "ERROR - Usage: python3 client.py <client_id> <port> [host]" in client("qwe 8040 localhost -s")
    assert "ERROR - Invalid port" in client("qwe 1002")
    assert "ERROR - Invalid port" in client("qwe 69746")