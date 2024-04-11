import sys
import tkinter as tk
from tkinter import filedialog
from md5 import md5
from sha1 import sha1
import sha256
from crc32 import crc32


def print_help_message():
    print(
        "Sepitor",
        "Usage: sepitor [<COMMAND>]\n",
        "Commands:\n\tcheck \tChecks Of Checksum Hash Of a File\n",
        "\thash \tHash a File",
    )


def hash_file():
    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.askopenfile()
    print(file_path)
    if file_path is None:
        print("No File Were Selected !")
        return

    file = open(file=file_path.name, mode="rb")
    data = file.read()
    hash_mode = ""
    while hash_mode not in ("md5", "sha1", "sha256", "crc32"):
        hash_mode = input(
            "Enter Hash Type (MD5, SHA1, SHA256, CRC32): "
        ).lower()
    print("Please Wait ...")
    hashed_data = None
    match hash_mode:
        case "md5":
            hashed_data = md5(str(data))
        case "sha1":
            hashed_data = sha1(data)
        case "sha256":
            hashed_data = sha256.generate_hash(data).hex()
        case "crc32":
            hashed_data = crc32(data)

    return {
        "hashed_data": hashed_data,
        "hash_mode": hash_mode,
        "file_name": file.name,
    }


def calc_hash():
    hashed_file = hash_file()
    print(
        f"{hashed_file['hash_mode'].upper()} Of File ",
        f"{hashed_file['file_name']} Is : {hashed_file['hashed_data']}",
    )


def check_hash():

    hashed_file = hash_file()

    hash_value = input(
        f"Enter Hash Value Of The File ({hashed_file['hash_mode'].upper()}):"
    )

    if hashed_file["hashed_data"] == hash_value:
        print("Hash Checks !!!")
        print(
            f"{hashed_file['hash_mode'].upper()} Of File ",
            f"{hashed_file['file_name']} Is Indeed : {hash_value}",
        )
    else:
        print("No Match !!")


def main(argv):
    if len(argv) <= 0:
        print_help_message()
        sys.exit(2)

    if argv[0] == "check":
        check_hash()
    elif argv[0] == "hash":
        calc_hash()
    else:
        print_help_message()


if __name__ == "__main__":
    main(sys.argv[1:])
