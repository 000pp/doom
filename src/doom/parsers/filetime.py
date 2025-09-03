from struct import unpack

def parse_filetime(filetime_bytes):
    try:
        if len(filetime_bytes) == 8:
            filetime = unpack('<Q', filetime_bytes)[0]
            if filetime == 0:
                return "Never"
            seconds = filetime / 10000000.0
            if seconds > 31536000:
                years = seconds / 31536000
                return f"{years:.1f} years"
            elif seconds > 86400:
                days = seconds / 86400
                return f"{days:.1f} days"
            else:
                hours = seconds / 3600
                return f"{hours:.1f} hours"
    except:
        pass
    return str(filetime_bytes)