import hashlib
import multiprocessing
import secrets
import string

allowed_chars = ''.join(c for c in string.printable if c not in '\n\r\t ')

def generate_secret(index: str, length: int = 16) -> str:
    return ''.join(secrets.choice(f"{allowed_chars}{str(index)}") for _ in range(length))

def worker(challenge: str, zeroes: str, shared_result: dict, index_counter: int, lock):
    while True:
        with lock:
            if shared_result.get("done"):
                return
            current_index = index_counter.value
            index_counter.value += 1

        secret = generate_secret(index = current_index)
        candidate = f"{challenge}{secret}"
        hash_value = hashlib.sha1(candidate.encode("utf-8")).hexdigest()
        if hash_value.startswith("0" * zeroes):
            with lock:
                shared_result["done"] = True
                shared_result["secret"] = secret
                shared_result["hash"] = hash_value
            return

def solve_challenge(challenge, zeroes):
    manager = multiprocessing.Manager()
    shared_result = manager.dict()
    shared_result["done"] = False

    index_counter = manager.Value("i", 0)
    lock = manager.Lock()

    processes = []
    for _ in range(multiprocessing.cpu_count()):
        p = multiprocessing.Process(target=worker, args=(
            challenge, zeroes, shared_result, index_counter, lock
        ))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    return shared_result.get("secret"), shared_result.get("hash")