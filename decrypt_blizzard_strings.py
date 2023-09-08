import idaapi
import ida_bytes
import idc

image_base = idaapi.get_imagebase()
used_addresses = set()  # Maintain a set of used addresses, we don't want to accidentally decrypt a string twice
decrypted_count = 0

def main():
    patterns = ["8B ? 83 E0 07", "8B ? ? ? ? ? 83 E0 07", "8B C2 48 8D ? ? ? ? ? ? ? ? ? ? 83 E0 07"]    
    print("=====BEGIN STRING DECRYPT=====")

    max_address = get_max_address()
    
    for pattern in patterns:
        current_decrypt_addr = find_decrypt(0, pattern, max_address)
        
        while current_decrypt_addr != idc.BADADDR:
            function = idaapi.get_func(current_decrypt_addr)
            sig_found_addr = current_decrypt_addr
            if function is None:
                current_decrypt_addr = find_decrypt(idc.next_head(sig_found_addr), pattern, max_address)
                continue

            while current_decrypt_addr > function.start_ea:
                current_decrypt_addr = idc.prev_head(current_decrypt_addr)
                if idc.print_insn_mnem(current_decrypt_addr) == "cmp":
                    break

            if current_decrypt_addr <= function.start_ea:
                current_decrypt_addr = find_decrypt(idc.next_head(sig_found_addr), pattern, max_address)
                continue

            is_encrypted_addr = idc.get_operand_value(current_decrypt_addr, 0)
            
            if is_encrypted_addr < image_base:
                current_decrypt_addr = find_decrypt(idc.next_head(sig_found_addr), pattern, max_address)
                continue

            if current_decrypt_addr in used_addresses:
                current_decrypt_addr = find_decrypt(idc.next_head(current_decrypt_addr), pattern, max_address)
                continue

            used_addresses.add(is_encrypted_addr)
            decrypt_string(current_decrypt_addr, is_encrypted_addr)
            
            current_decrypt_addr = find_decrypt(idc.next_head(sig_found_addr), pattern, max_address)

    print("Decrypted %s strings" % decrypted_count)
    print("=====END STRING DECRYPT=====")

def get_max_address():
    # Get the max address
    max_address = 0
    segment = idc.get_first_seg()
    
    while segment != idc.BADADDR:
        max_address = idc.get_segm_end(segment)
        segment = idc.get_next_seg(segment)
    
    return max_address

def parse_pattern(pattern_str):
    # Parse our pattern
    pattern = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(pattern, image_base, pattern_str, 16)
    
    if err:
        print(f"Failed to parse pattern: {err}")
        return None
    
    return pattern

def find_decrypt(start_addr, pattern, max_address):
    parsed_pattern = parse_pattern(pattern)
    address = ida_bytes.bin_search(start_addr, max_address, parsed_pattern, ida_bytes.BIN_SEARCH_FORWARD)
    
    if address != idc.BADADDR:
        return address
    
    return idc.BADADDR

def decrypt_string(current_decrypt_addr, is_encrypted_addr):
    global decrypted_count
    is_encrypted = ida_bytes.get_byte(is_encrypted_addr)
    key_addr = is_encrypted_addr - 11

    if is_encrypted == 1:
        key = []
        string_len = ida_bytes.get_word(key_addr + 8)
        encrypted_string = []

        length = int(string_len & 0xFFFFFF)

        if 0 < length < 1000:
            for i in range(0, 8):
                key.append(ida_bytes.get_byte(key_addr + i))

            for i in range(0, length):
                encrypted_string.append(ida_bytes.get_byte(key_addr + 0xC + i))

            decrypted_string = ""
            
            for i in range(0, length):
                decrypted_char_code = key[i & 7] ^ encrypted_string[i]
                decrypted_string += chr(decrypted_char_code)
                ida_bytes.patch_byte(key_addr + 0xC + i, ord(decrypted_string[i]))

            ida_bytes.create_strlit(key_addr + 0xC, string_len, 0)
            ida_bytes.patch_byte(key_addr + 11, 0)  # is_encrypted

            if "\n" in decrypted_string:
                decrypted_string = decrypted_string.replace("\n", " ")

            if decrypted_string != "Unknown" and decrypted_string != "":
                decrypted_count += 1
                print("%s -> %s" % (hex(current_decrypt_addr), decrypted_string))
    elif is_encrypted == 0:
        string_len = ida_bytes.get_word(key_addr + 8)
        decrypted_string = ""
        
        for i in range(0, (string_len & 0xFFFFFF)):
            decrypted_string += chr(ida_bytes.get_byte(key_addr + 0xC + i))

        if "\n" in decrypted_string:
            decrypted_string = decrypted_string.replace("\n", " ")

        if decrypted_string != "Unknown" and decrypted_string != "":
            decrypted_count += 1
            print("%s -> %s" % (hex(current_decrypt_addr), decrypted_string))
    return

if __name__ == "__main__":
    main()
