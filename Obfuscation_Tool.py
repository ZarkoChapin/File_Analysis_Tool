import os
import csv
import hashlib
import magic
import requests
import time
import datetime
import requests
import stat
import sys
import zipfile
import tarfile


VIRUS_TOTAL_API = "***YOUR API HERE***"
supported_extensions = [".zip", ".sitx", ".tar", ".gz", ".tgz", ".rar", ".7z"]


# function to analyze a file
def file_analysis(file_path):
    try:
        # open the file in binary mode and read its contents
        with open(file_path, "rb") as f:
            file_contents = f.read()

        # compute the md5 hash of the file contents
        md5_hash = hashlib.md5(file_contents).hexdigest()

        # extract metadata about the file
        file_size = os.path.getsize(file_path)
        file_permissions = stat.filemode(os.stat(file_path).st_mode)
        file_created_time = datetime.datetime.fromtimestamp(
            os.path.getctime(file_path)
        ).strftime("%Y-%m-%d %H:%M:%S")
        file_modified_time = datetime.datetime.fromtimestamp(
            os.path.getmtime(file_path)
        ).strftime("%Y-%m-%d %H:%M:%S")
        file_accessed_time = datetime.datetime.fromtimestamp(
            os.path.getatime(file_path)
        ).strftime("%Y-%m-%d %H:%M:%S")

        # perform additional analysis on the file, such as extracting additional metadata

        # format the analysis results as a string
        analysis_results = f"\nFilepath: {file_path}\nMD5 Hash: {md5_hash}\nFile Size: {file_size} bytes\nFile Permissions: {file_permissions}\nFile Created Time: {file_created_time}\nFile Modified Time: {file_modified_time}\nFile Accessed Time: {file_accessed_time}\n"

        print(analysis_results)

    # basic error handling
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
    except PermissionError:
        print(f"Error: Permission denied for file {file_path}")
    except Exception as e:
        print(f"Error: {e}")


# function to search for a file in a directory
def search_files(directory, search_term):
    exact_matches = []
    partial_matches = []

    # traverse the directory and search for the file
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            if search_term.lower() == file_name.lower():
                exact_matches.append(os.path.join(root, file_name))
            else:
                count = 0
                for i, char in enumerate(search_term):
                    if i < len(file_name) and char.lower() == file_name[i].lower():
                        count += 1
                        if count == len(search_term):
                            partial_matches.append(os.path.join(root, file_name))
                            break
                    else:
                        count = 0

    # print the results, showing exact matches first, then partial matches
    if len(exact_matches) == 0 and len(partial_matches) == 0:
        print(f"No matches found for '{search_term}' in {directory}")
    else:
        if len(exact_matches) > 0:
            print("Exact Matches:")
            for match in exact_matches:
                print(match)

        if len(partial_matches) > 0:
            print("Partial Matches:")
            for match in partial_matches:
                print(match)


# function to generate the MD5 hash of a file
def get_md5(file_path):
    while True:
        # check if the path exists
        if not os.path.exists(file_path):
            print("Error: path does not exist.")
            continue

        # check if the path is a directory or a file, and compute the hash accordingly
        if os.path.isdir(file_path):
            md5_hash = hashlib.md5()

            for root, dirs, files in os.walk(file_path):
                for file in files:
                    with open(os.path.join(root, file), "rb") as f:
                        data = f.read()
                        md5_hash.update(data)

            print(f"\nMD5 hash: {md5_hash.hexdigest()}\n")
            break
        else:
            with open(file_path, "rb") as f:
                data = f.read()
                md5_hash = hashlib.md5(data)

            print(f"\nMD5 hash: {md5_hash.hexdigest()}\n")
            break


# function to get the modified, accessed, and created times of a file in human-readable format
def get_file_times(file_path):
    if not os.path.exists(file_path):
        raise ValueError("File path does not exist")
    st = os.stat(file_path)
    created = datetime.datetime.fromtimestamp(st.st_ctime)
    modified = datetime.datetime.fromtimestamp(st.st_mtime)
    accessed = datetime.datetime.fromtimestamp(st.st_atime)
    os.utime(file_path, (st.st_atime, st.st_mtime))
    return created, modified, accessed


# function to get hash of file/directory
def get_file_hash(file_path):
    if os.path.isdir(file_path):
        raise ValueError("Directory not supported")
    with open(file_path, "rb") as f:
        data = f.read()
    return hashlib.md5(data).hexdigest()


# function to scan a file for malware
def scan_for_malware(file_path):
    file_hash = get_file_hash(file_path)
    params = {"apikey": VIRUS_TOTAL_API, "resource": file_hash}
    response = requests.get(
        "https://www.virustotal.com/vtapi/v2/file/report", params=params
    )
    if response.status_code == 200:
        json_response = response.json()
        if json_response["response_code"] == 1:
            positives = json_response["positives"]
            total = json_response["total"]
            if positives > 0:
                print(f'Malware detected: {json_response["permalink"]}')
            else:
                print("No malware detected")
            print(
                f'Scanned on: {json_response["scan_date"]}, '
                f"Total engines used: {total}, "
                f"Engines detected malware: {positives}"
            )
        else:
            print("\nFile not found in VirusTotal database.\n")
    else:
        print("\nError retrieving results from VirusTotal\n")


# function to detect the file type
def detect_file_type(file_path):
    file_type = magic.from_file(file_path)
    return file_type


# function to write the file info to a CSV file
def write_to_csv(file_data):
    with open("file_info.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "File Name",
                "File Type",
                "MD5 Hash",
                "Created Time",
                "Modified Time",
                "Accessed Time",
                "Malware Detection",
            ]
        )
        for data in file_data:
            writer.writerow(data)


# Define a function to check if a file is compressed and return its size
def check_compressed_file(filename):
    file_size = os.path.getsize(filename)
    if filename.endswith(".zip"):
        try:
            with zipfile.ZipFile(filename) as zf:
                is_compressed = True
        except:
            is_compressed = False
    elif filename.endswith(".sitx"):
        # Implement checking for SITX format
        is_compressed = False
    elif filename.endswith(".7z"):
        # Implement checking for 7z format
        is_compressed = False
    elif filename.endswith(".rar"):
        # Implement checking for RAR format
        is_compressed = False
    elif filename.endswith(".gz"):
        try:
            with open(filename, "rb") as f:
                is_compressed = f.read(2) == b"\x1f\x8b"
        except:
            is_compressed = False
    elif filename.endswith(".tgz"):
        try:
            with open(filename, "rb") as f:
                is_compressed = f.read(2) == b"\x1f\x8b"
        except:
            is_compressed = False
    elif filename.endswith(".tar"):
        try:
            with tarfile.open(filename) as tf:
                is_compressed = True
        except:
            is_compressed = False
    else:
        is_compressed = False
    return is_compressed, file_size


# function to display the menu
def display_menu():
    while True:
        print("Please select an option:\n")
        print(
            "1. Analyze File (Displays path, hash, size, permissions, MAC times, and type)"
        )
        print("2. Search for file")
        print("3. Generate MD5 hash")
        print("4. Check file times (Created, Modified, Accessed)")
        print("5. Check for malware (VirusTotal)")
        print("6. Output file info to CSV (Desktop)")
        print("7. Check for compressed files")
        print("8. Exit\n")
        choice = input("Enter your choice: ")
        if choice == "1":
            while True:
                # Get user input for the directory path
                dir_path = input("Enter the directory path: ")
                file_analysis(dir_path)

                # Ask if the user wants to traverse another directory or exit
                choice = input("Do you want to traverse another directory? (y/n): ")
                if choice.lower() != "y":
                    break
        elif choice == "2":
            while True:
                try:
                    # Get user input for the directory path and filename
                    directory = input("Enter the directory to search in: ")
                    filename = input("Enter the filename to search for: ")

                    # Call the function with the user input
                    search_files(directory, filename)

                    # Ask if the user wants to search again or exit
                    choice = input("Do you want to search again? (y/n): ")
                    if choice.lower() != "y":
                        break
                except FileNotFoundError:
                    print("Directory not found. Please try again.")
                except PermissionError:
                    print("Permission denied. Please try again.")
        elif choice == "3":
            while True:
                # Get user input for the file path
                file_path = input("Enter file path: ")
                try:
                    # Call the function with the user input
                    md5_hash = get_md5(file_path)
                except ValueError as e:
                    print(f"Error: {e}")
                    # Ask if the user wants to search again or exit
                again = input("Do you want to check another file? (y/n) ")
                if again.lower() != "y":
                    break
        elif choice == "4":
            while True:
                file_path = input("Enter file path: ")
                try:
                    created, modified, accessed = get_file_times(file_path)
                    print(
                        f"\nCreated: {created}\nModified: {modified}\nAccessed: {accessed}\n"
                    )
                except ValueError as e:
                    print(f"Error: {e}")
                again = input("Do you want to check another file? (y/n) ")
                if again.lower() != "y":
                    break
                get_file_times(file_path)
        elif choice == "5":
            while True:
                file_path = input("Enter file path: ")
                try:
                    scan_for_malware(file_path)
                except ValueError as e:
                    print(f"Error: {e}")
                again = input("Do you want to check another file? (y/n) ")
                if again.lower() != "y":
                    break
        elif choice == "6":
            file_data = []
            dir_path2 = input("Enter the directory path: ")
            # traverse the directory, get the file info and MD5 hash
            for root, dirs, files in os.walk(dir_path2):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_type = detect_file_type(file_path)
                    md5_hash = get_md5(file_path)

                    # get the timestamps
                    created_time = os.path.getctime(file_path)
                    modified_time = os.path.getmtime(file_path)
                    accessed_time = os.path.getatime(file_path)

                    # convert timestamps to human-readable format
                    mod_ctime = time.ctime(created_time)
                    mod_mtime = time.ctime(modified_time)
                    mod_atime = time.ctime(accessed_time)

                    # check for malware
                    malware_status = scan_for_malware(file_path)
                    if malware_status == "Malware detected":
                        print(f"Malware detected in {file_path}\n")
                    else:
                        print(f"No malware detected in {file_path}\n")
                    file_data.append(
                        [
                            file,
                            file_type,
                            md5_hash,
                            mod_ctime,
                            mod_mtime,
                            mod_atime,
                            malware_status,
                        ]
                    )
            # write the file data to a CSV file
            write_to_csv(file_data)
            print("\n*****Output to file_info.csv*****\n")
        elif choice == "7":
            while True:
                try:
                    file_path = input("Enter file path: ")
                    # check if the path exists and is a file or folder
                    if not os.path.exists(file_path):
                        print("Error: File or directory not found")
                        sys.exit()
                    elif os.path.isfile(file_path):
                        # if the path is a file, check if it is compressed
                        is_compressed, file_size = check_compressed_file(file_path)
                        if is_compressed:
                            print(
                                f"***HIT***: {file_path} is compressed, size: {file_size} bytes.\n"
                            )
                        else:
                            print(f"{file_path} is not compressed\n")
                    else:
                        # if the path is a directory, traverse it and check if any files are compressed
                        for root, dirs, files in os.walk(file_path):
                            for file in files:
                                file_path = os.path.join(root, file)
                                is_compressed, file_size = check_compressed_file(
                                    file_path
                                )
                                if is_compressed:
                                    print(
                                        f"***HIT***: {file_path} is compressed, size: {file_size} bytes.\n"
                                    )
                                else:
                                    print(f"{file_path} is not compressed\n")
                    again = input("Do you want to check another file? (y/n) ")
                    if again.lower() != "y":
                        break
                except ValueError as e:
                    print(f"Error: {e}")
        elif choice == "8":
            break
        else:
            print("Invalid choice, please try again")


# call the display menu function to start the script
display_menu()
