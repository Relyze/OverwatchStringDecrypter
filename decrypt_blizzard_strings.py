import idaapi
import ida_bytes
import idc

DECRYPTED_FLAG = 0
ENCRYPTED_FLAG = 1

decrypted_addresses = set()
decrypted_count = 0

def get_max_address():
    max_address = 0
    segment = idc.get_first_seg()

    while segment != idc.BADADDR:
        max_address = max(max_address, idc.get_segm_end(segment))
        segment = idc.get_next_seg(segment)
    return max_address

def find_cmp(function, current_decrypt_addr):
    while current_decrypt_addr > function.start_ea:
        current_decrypt_addr = idc.prev_head(current_decrypt_addr)
        if idc.print_insn_mnem(current_decrypt_addr) == "cmp":
            return current_decrypt_addr
    return idc.BADADDR

def find_decrypt(start_addr, compiled_pattern, max_address):
    if compiled_pattern is None:
        return idc.BADADDR

    return ida_bytes.bin_search(start_addr, max_address, compiled_pattern, ida_bytes.BIN_SEARCH_FORWARD)

def parse_pattern(pattern_str, image_base):
    pattern = ida_bytes.compiled_binpat_vec_t()
    err = ida_bytes.parse_binpat_str(pattern, image_base, pattern_str, 16)

    if err:
        print(f"[Error] Failed to parse pattern: {err}")
        return None

    return pattern

def main():
    global decrypted_addresses, decrypted_count
    decrypted_addresses.clear()
    decrypted_count = 0
    image_base = idaapi.get_imagebase()
    max_address = get_max_address()

    patterns = [ "8B ?? ?? ?? ?? ?? ?? FF FF FF 00 3B", "8B ?? ?? ?? ?? ?? ?? FF FF FF 00 ?? 3B", "8B ?? ?? ?? ?? ?? ?? ?? FF FF FF 00 3B", "8B ?? ?? ?? ?? ?? ?? ?? FF FF FF 00 ?? 3B" ]
    compiled_patterns = [parse_pattern(pattern, image_base) for pattern in patterns]

    print("[OWSD] Begin Decryption")
    for compiled_pattern in compiled_patterns:
        current_decrypt_addr = find_decrypt(0, compiled_pattern, max_address)

        while current_decrypt_addr != idc.BADADDR:
            try:
                # Extract the address if current_decrypt_addr is a tuple
                if isinstance(current_decrypt_addr, tuple):
                    if current_decrypt_addr[0] > max_address:
                        break

                current_decrypt_addr = current_decrypt_addr[0]
                function = idaapi.get_func(current_decrypt_addr)
                sig_found_addr = current_decrypt_addr

                if function is None:
                    current_decrypt_addr = find_decrypt(idc.next_head(sig_found_addr), compiled_pattern, max_address)
                    continue

                current_decrypt_addr = find_cmp(function, current_decrypt_addr)

                if current_decrypt_addr < function.start_ea:
                    current_decrypt_addr = find_decrypt(idc.next_head(sig_found_addr), compiled_pattern, max_address)
                    continue

                is_encrypted_addr = idc.get_operand_value(current_decrypt_addr, 0)
                if is_encrypted_addr < image_base:
                    current_decrypt_addr = find_decrypt(idc.next_head(sig_found_addr), compiled_pattern, max_address)
                    continue

                decrypt_string(current_decrypt_addr, is_encrypted_addr)

            except Exception as e:
                print(f"[Error] Failed to process instruction at {hex(current_decrypt_addr)}: {e}")

            current_decrypt_addr = find_decrypt(idc.next_head(sig_found_addr), compiled_pattern, max_address)

    print(f"[OWSD] Decrypted {decrypted_count} strings")
    print("[OWSD] End Decryption")

def decrypt_string(current_decrypt_addr, is_encrypted_addr):
    global decrypted_count, decrypted_addresses

    if is_encrypted_addr in decrypted_addresses:
        return
    decrypted_addresses.add(is_encrypted_addr)

    decrypted_string = ""
    try:
        is_encrypted = ida_bytes.get_byte(is_encrypted_addr)
        key_addr = is_encrypted_addr - 0xB
        key = []
        string_len = ida_bytes.get_word(key_addr + 0x8)
        encrypted_string = []

        if is_encrypted == ENCRYPTED_FLAG and 0 < (string_len & 0xFFFFFF):
            for i in range(8):
                key.append(ida_bytes.get_byte(key_addr + i))

            for i in range(string_len & 0xFFFFFF):
                encrypted_string.append(
                    ida_bytes.get_byte(key_addr + 0xC + i))
            decrypted_string = "".join(
                [chr(key[i & 7] ^ encrypted_string[i]) for i in range(string_len & 0xFFFFFF)])

            for i, char in enumerate(decrypted_string):
                ida_bytes.patch_byte(key_addr + 0xC + i, ord(char))

            ida_bytes.create_strlit(key_addr + 0xC, string_len, 0)
            ida_bytes.patch_byte(key_addr + 0xB, 0)  # is_encrypted

        elif is_encrypted == DECRYPTED_FLAG:
            decrypted_string = "".join(
                [chr(ida_bytes.get_byte(key_addr + 0xC + i)) for i in range(string_len & 0xFFFFFF)])

        decrypted_string = decrypted_string.replace("\n", " ")
        decrypted_string = decrypted_string.replace("\t", "      ")

        if decrypted_string:
            print(f"{hex(current_decrypt_addr)} -> {decrypted_string}")
            decrypted_count += 1

    except Exception as e:
        print(
            f"[Error] Failed to decrypt string at {hex(current_decrypt_addr)}: {e}")

if __name__ == "__main__":
    main()
