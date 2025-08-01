import ssl
import hashlib
import asyncio
import challengesolver
from datetime import datetime
import argparse

async def run_client(ssl_context: ssl.SSLContext, host: str ='localhost', port: int =8023):
    try:
        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
    except ConnectionRefusedError:
        print("The remote computer refused the network connection")
        exit()
    authdata = ""
    try:
        while True:
            line = await reader.readline()
            if not line:  # connection closed by server
                print("Connection closed by server.")
                break

            line = line.decode("utf-8").strip().split(' ')

            if line[0] == "HELO":
                writer.write(("TOAKUEI\n").encode("utf-8"))
                await writer.drain()
            elif line[0] == "ERROR":
                print("ERROR: " + " ".join(line[1:]))
                break
            elif line[0] == "END":
                writer.write(("OK\n").encode("utf-8"))
                await writer.drain()
                break
            elif line[0] == "POW":
                authdata, difficulty = line[1], line[2]
                authdata = authdata
                # Run your PoW solver in executor to avoid blocking event loop
                loop = asyncio.get_running_loop()
                secret, hash_val = await loop.run_in_executor(None, challengesolver.solve_challenge, authdata, int(difficulty))
                print(f"Secret: {secret}\nHash: {hash_val}")
                writer.write((f"{secret}\n").encode("utf-8"))
                await writer.drain()
            elif line[0] == "NAME":
                while True:
                    user_input = await asyncio.to_thread(input, f"{line[0]}: ")
                    user_input = user_input.strip()
                    if not user_input:
                        print("Enter Value. Should not be empty.")
                        continue
                    break
                hashdigest = hashlib.sha1((authdata + line[1]).encode("utf-8")).hexdigest()
                writer.write((f"{hashdigest} {user_input.strip()}\n").encode("utf-8"))
                await writer.drain()
            elif line[0] == "MAILNUM":
                # here you specify, how many email addresses you want to send
                # each email is asked separately up to the number specified in MAILNUM
                while True:
                    user_input = await asyncio.to_thread(input, f"{line[0]}: ")
                    user_input = user_input.strip()
                    if not user_input or not user_input.isdigit():
                        print("Enter a non-empty numeric value.")
                        continue
                    break
                hashdigest = hashlib.sha1((authdata + line[1]).encode("utf-8")).hexdigest()
                writer.write((f"{hashdigest} {user_input.strip()}\n").encode("utf-8"))
                await writer.drain()
            elif line[0].startswith("MAIL") and "".join(list(line[0])[4:]).isdigit():
                while True:
                    user_input = await asyncio.to_thread(input, f"{line[0]}: ")
                    user_input = user_input.strip()
                    if not user_input or len(user_input.split("@")) != 2:
                        print("Enter a valid email address.")
                        continue
                    break
                hashdigest = hashlib.sha1((authdata + line[1]).encode("utf-8")).hexdigest()
                writer.write((f"{hashdigest} {user_input.strip()}\n").encode("utf-8"))
                await writer.drain()
            elif line[0] == "SKYPE":
                while True:
                    user_input = await asyncio.to_thread(input, f"{line[0]}. If no Skype account for the interview enter N/A: ")
                    user_input = user_input.strip()
                    if not user_input:
                        print("Enter Value. Should not be empty.")
                        continue
                    break
                hashdigest = hashlib.sha1((authdata + line[1]).encode("utf-8")).hexdigest()
                writer.write((f"{hashdigest} {user_input.strip()}\n").encode("utf-8"))
                await writer.drain()
            elif line[0] == "BIRTHDATE":
                # here please specify your birthdate in the format %d.%m.%Y
                while True:
                    # Run blocking input() call in a thread to not block asyncio loop
                    user_input = await asyncio.to_thread(input, f"{line[0]}. specify your birthdate in the format %d.%m.%Y: ")
                    user_input = user_input.strip()
                    try:   
                        datetime.strptime(user_input, "%d.%m.%Y")
                        break  # valid input, exit loop
                    except ValueError:
                        print("Invalid format! Please enter date as DD.MM.YYYY.")
                hashdigest = hashlib.sha1((authdata + line[1]).encode("utf-8")).hexdigest()
                writer.write((f"{hashdigest} {user_input.strip()}\n").encode("utf-8"))
                await writer.drain()
            elif line[0] == "COUNTRY":
                # country where you currently live and where the specified address is
                # please use only the names from this web site:
                # https://www.countries−ofthe−world.com/all−countries.html
                while True:
                    user_input = await asyncio.to_thread(input, f"{line[0]}. country where you currently live and where the specified addressis. Please use only the names from this web site https://www.countries−ofthe−world.com/all−countries.html: ")
                    user_input = user_input.strip()
                    if not user_input:
                        print("Enter Value. Should not be empty.")
                        continue
                    break
                hashdigest = hashlib.sha1((authdata + line[1]).encode("utf-8")).hexdigest()
                writer.write((f"{hashdigest} {user_input.strip()}\n").encode("utf-8"))
                await writer.drain()
            elif line[0] == "ADDRNUM":
                # specifies how many lines your address has, this address should
                # be in the specified country
                while True:
                    user_input = await asyncio.to_thread(input, f"{line[0]}: ")
                    user_input = user_input.strip()
                    if not user_input or not user_input.isdigit():
                        print("Enter a non-empty numeric value.")
                        continue
                    break
                hashdigest = hashlib.sha1((authdata + line[1]).encode("utf-8")).hexdigest()
                user_input = "1"
                writer.write((f"{hashdigest} {user_input.strip()}\n").encode("utf-8"))
                await writer.drain()
            elif line[0].startswith("ADDRLINE") and "".join(list(line[0])[8:]).isdigit():
                while True:
                    user_input = await asyncio.to_thread(input, f"{line[0]}: ")
                    user_input = user_input.strip()
                    if not user_input:
                        print("Enter Value. Should not be empty.")
                        continue
                    break
                hashdigest = hashlib.sha1((authdata + line[1]).encode("utf-8")).hexdigest()
                writer.write((f"{hashdigest} {user_input.strip()}\n").encode("utf-8"))
                await writer.drain()
            else:
                writer.write(("ACK\n").encode("utf-8"))
                await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()
        print("Connection closed cleanly.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--certPath', required=True, help="Path to the PEM certificate file")
    parser.add_argument('-H', '--host', default='localhost', help="Server hostname or IP address")
    parser.add_argument('-p', '--port', type=int, default=3336, help="Server port number")

    args = parser.parse_args()

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
         ssl_context.load_cert_chain(certfile=str(args.certPath))
    except FileNotFoundError:
         print("Unable to locate PEM file. Exiting")
         exit()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    asyncio.run(run_client(ssl_context= ssl_context, host=str(args.host), port=int(args.port)))
