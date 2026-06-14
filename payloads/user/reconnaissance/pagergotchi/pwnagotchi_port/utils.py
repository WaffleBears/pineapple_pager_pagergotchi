"""
Utility functions - copied from original pwnagotchi with minimal changes
Simplified for Pagergotchi (removed toml config loading, kept essential functions)
"""

import logging
import glob
import os
import subprocess
import json
from datetime import datetime
from enum import Enum


def parse_version(version):
    """Converts a version str to tuple for comparison"""
    return tuple(version.split('.'))


def merge_config(user, default):
    """Recursively merge user config into default config"""
    if isinstance(user, dict) and isinstance(default, dict):
        for k, v in default.items():
            if k not in user:
                user[k] = v
            else:
                user[k] = merge_config(user[k], v)
    return user


def secs_to_hhmmss(secs):
    """Convert seconds to HH:MM:SS format"""
    mins, secs = divmod(int(secs), 60)
    hours, mins = divmod(mins, 60)
    return '%02d:%02d:%02d' % (hours, mins, secs)


def total_unique_handshakes(path):
    """Count unique handshake files in path (prefer .22000, don't double-count)"""
    # .22000 files are hashcat format - count these first (pineapd creates both .pcap and .22000)
    hash_files = glob.glob(os.path.join(path, "*.22000"))
    if hash_files:
        return len(hash_files)
    # Fallback to pcap/pcapng if no .22000 files
    pcap_files = glob.glob(os.path.join(path, "*.pcap"))
    pcapng_files = glob.glob(os.path.join(path, "*.pcapng"))
    return len(pcap_files) + len(pcapng_files)


def iface_channels(ifname):
    """Get supported channels for interface"""
    channels = []
    try:
        result = subprocess.run(
            ['iw', ifname, 'info'],
            capture_output=True, text=True, timeout=5
        )
        phy_match = None
        for line in result.stdout.split('\n'):
            if 'wiphy' in line:
                phy_match = line.split()[-1]
                break

        if phy_match is not None:
            result = subprocess.run(
                ['iw', f'phy{phy_match}', 'info'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                low = line.lower()
                if 'mhz' in low and 'disabled' not in low and '[' in line and ']' in line:
                    ch = line.split('[')[1].split(']')[0]
                    try:
                        channels.append(int(ch))
                    except ValueError:
                        pass
    except Exception as e:
        logging.debug(f"Error getting channels: {e}")

    if not channels:
        logging.warning("iface_channels(%s) found none; defaulting to 2.4GHz only", ifname)
        channels = list(range(1, 12))

    return channels


BUILTIN_IFACE = 'wlan1mon'
MK7AC_IFACE = 'wlan2mon'


def iface_exists(iface):
    return os.path.exists('/sys/class/net/%s' % iface)


def iface_is_monitor(iface):
    try:
        result = subprocess.run(['iw', 'dev', iface, 'info'],
                                capture_output=True, text=True, timeout=5)
        return result.returncode == 0 and 'type monitor' in result.stdout
    except Exception:
        return False


def mk7ac_available():
    return iface_exists(MK7AC_IFACE) and iface_is_monitor(MK7AC_IFACE)


def resolve_interfaces(choice, pmkid=True):
    choice = (choice or 'auto').strip().lower()
    have_mk7ac = mk7ac_available()
    builtin, mk7 = BUILTIN_IFACE, MK7AC_IFACE
    warning = None

    if choice in ('mk7ac', mk7, 'wlan2'):
        if have_mk7ac:
            pineapd = mk7
            pmkid_if = builtin if iface_exists(builtin) else None
        else:
            pineapd = builtin
            pmkid_if = None
            warning = 'MK7AC (wlan2mon) not found - using built-in'
    elif choice in ('builtin', builtin, 'wlan1'):
        pineapd = builtin
        pmkid_if = None
    else:
        pineapd = builtin
        pmkid_if = mk7 if have_mk7ac else None

    if not pmkid:
        pmkid_if = None

    if not iface_exists(pineapd):
        warning = '%s missing' % pineapd

    return {
        'pineapd': pineapd,
        'pmkid': pmkid_if,
        'have_mk7ac': have_mk7ac,
        'warning': warning,
    }


def parse_22000_line(line):
    line = line.strip()
    if not line.startswith('WPA*'):
        return None
    parts = line.split('*')
    if len(parts) < 6:
        return None
    htype = parts[1]
    ap = parts[3].lower()
    sta = parts[4].lower()
    essid = ''
    try:
        essid = bytes.fromhex(parts[5]).decode('utf-8', errors='ignore')
    except ValueError:
        essid = ''
    if len(ap) != 12 or len(sta) != 12:
        return None
    return {
        'type': htype,
        'ap': ':'.join(ap[i:i + 2] for i in range(0, 12, 2)),
        'sta': ':'.join(sta[i:i + 2] for i in range(0, 12, 2)),
        'essid': essid,
        'key': '%s*%s*%s' % (htype, ap, sta),
    }


def scan_handshake_captures(path):
    captures = {}
    for f in glob.glob(os.path.join(path, '*.22000')):
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    rec = parse_22000_line(line)
                    if rec:
                        rec['file'] = f
                        captures[rec['key']] = rec
        except Exception:
            continue
    return captures


class WifiInfo(Enum):
    """Fields you can extract from a pcap file"""
    BSSID = 0
    ESSID = 1
    ENCRYPTION = 2
    CHANNEL = 3
    FREQUENCY = 4
    RSSI = 5


class FieldNotFoundError(Exception):
    pass


def md5(fname):
    """Calculate MD5 hash of file"""
    import hashlib
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


class StatusFile(object):
    """Status file handler for persistent data"""
    def __init__(self, path, data_format='raw'):
        self._path = path
        self._updated = None
        self._format = data_format
        self.data = None

        if os.path.exists(path):
            self._updated = datetime.fromtimestamp(os.path.getmtime(path))
            with open(path) as fp:
                if data_format == 'json':
                    self.data = json.load(fp)
                else:
                    self.data = fp.read()

    def data_field_or(self, name, default=""):
        if self.data is not None and name in self.data:
            return self.data[name]
        return default

    def newer_then_minutes(self, minutes):
        return self._updated is not None and ((datetime.now() - self._updated).seconds / 60) < minutes

    def newer_then_hours(self, hours):
        return self._updated is not None and ((datetime.now() - self._updated).seconds / (60 * 60)) < hours

    def newer_then_days(self, days):
        return self._updated is not None and (datetime.now() - self._updated).days < days

    def update(self, data=None):
        self._updated = datetime.now()
        self.data = data
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, 'w') as fp:
            if data is None:
                fp.write(str(self._updated))
            elif self._format == 'json':
                json.dump(self.data, fp)
            else:
                fp.write(data)
