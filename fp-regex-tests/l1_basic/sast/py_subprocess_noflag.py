import subprocess
def ping_target(host):
    subprocess.run(["ping", "-c", "1", host], check=True)
