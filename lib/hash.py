# stdlib
import hashlib


# =============================================================================
#
# functions
#
# =============================================================================

# =============================================================================
# hash_string
# =============================================================================
def hash_string(string: str) -> str:
    return hashlib.sha256(string.encode('utf-8')).hexdigest()


# =============================================================================
# hash_list
# =============================================================================
def hash_list(string_list: list) -> str:
    return hash_string(''.join(string_list))


# =============================================================================
# hash_file
# =============================================================================
def hash_file(file_path: str) -> str:
    BUFFER_SIZE = 65536
    file_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while True:
            file_data = file.read(BUFFER_SIZE)
            if not file_data:
                break
            file_hash.update(file_data)
    return file_hash.hexdigest()
