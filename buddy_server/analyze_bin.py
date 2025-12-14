
import string

def extract_strings(filename, min_length=10):
    with open(filename, 'rb') as f:
        data = f.read()
    
    result = []
    current_string = ""
    
    printable = set(bytes(string.printable, 'ascii'))
    
    for byte in data:
        if byte in printable and byte not in [0x09, 0x0A, 0x0D]: # Exclude tabs/newlines to avoid breaking simple strings
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                result.append(current_string)
            current_string = ""
            
    if len(current_string) >= min_length:
        result.append(current_string)
        
    return result

def filter_strings(strings):
    keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN", 
                "Error", "Fail", "Connect", "Socket", "Port", "IP", "Buddies", "Friend", "User",
                "Udp", "Center", "Register", "CTR_", "Listen", "REG_LOGIN", "REC_CENTER", "CENTER_",
                "Command", "CONFIG", "INIT", "Warning", "System", "Thread", "Queue", "Packet", "Msg"]
    filtered = []
    for s in strings:
        # Check if it looks like code or SQL or meaningful text
            filtered.append(s)
            
    return filtered

if __name__ == "__main__":
    binaries = [
        "c:/Users/Eletrocel/.gemini/antigravity/playground/tachyon-glenn/3 - SERVIDOR/BuddyServ/BuddyServ2.exe"
    ]
    
    all_strings = []
    
    print("Starting DEEP DUMP analysis on all binaries...")
    
    for bin_path in binaries:
        print(f"Analyzing {bin_path}...")
        try:
            # Lower min_length to catch short commands (e.g. 3-4 chars like 'cmd')
            strs = extract_strings(bin_path, min_length=4) 
            all_strings.extend([f"[{bin_path.split('/')[-1]}] {s}" for s in strs])
        except Exception as e:
            print(f"Skipping {bin_path}: {e}")

    # Aggressive Filtering? User asked for "extrai ate a alma" (extract soul).
    # Ideally we dump everything to a huge file, but let's filter for Packet-like structures 
    # and SQL to be useful, while keeping the raw dump option.
    
    # We will search for ANY string containing:
    # SVC_, CTR_, DBIN_, % (format strings), SELECT, INSERT, UPDATE, DELETE
    
    interesting_keywords = [
        "SVC_", "CTR_", "DBIN_", "REG_", "CENTER_", "BROKER_", 
        "SELECT", "INSERT", "UPDATE", "DELETE", "Expected", "Failed", 
        "Packet", "Socket", "Context", "User", "Game", "Buddy",
        "Invite", "INVITE", "Request", "REQUEST", "Add", "Friend", "Msg", "Chat"
    ]
    
    filtered_soul = []
    
    for s in all_strings:
        # Check if it has interesting keyword OR looks like a hex code OR looks like a struct
        if any(k in s for k in interesting_keywords) or "%" in s:
            filtered_soul.append(s)
            
    # Save EVERYTHING interesting
    with open("full_soul_dump.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(filtered_soul))
        
    print(f"Dumped {len(filtered_soul)} interesting strings to full_soul_dump.txt")
