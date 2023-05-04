# File Analysis Tool

# Introduction
Welcome to a basic file analyis tool created in python. This tool runs a variety of functions that can help the user collect metadata of files/directories, search for files, generate hashes, etc. More detailed descriptions will be given for each of the 7 functions this script has. To run, make sure you have python installed.

# Requirements
This script only requires installation of the latest version of python, which can be found at https://www.python.org/downloads/

# Functions
This script houses 7 different functions that help with basic file/directory analysis. I will explain the details of each function below:

1) Analyzes files: This option will prompt you for a file path (If the path is a directory, you will receive an error. This option only works for specific files). Once the input is taken, the function will return file path, MD5 hash, file size, file permissions, created time, modified time, and accessed time. Once completed, the user will be asked if they would like to traverse another directory and, if not, looped backed to the main menu.

2) File Search: The search function will first ask the user what directory they would like to search in (i.e. C:\ for whole machine), then they will be asked for the file they would like to search for. The script should return exact matches and partial matches based off how many characters are in similar order. Once the files are found, the user will be prompted if they would like to search again and looped back to the main menu, if not.

3) MD5 Hashing: This will prompt the user for a path of a file or directory they would like the MD5 hash from. This will then display the hash of the file to the user and ask them if they would like to hash another file, with loopback to main menu if not.

4) Check file times: This function prompts the user for a file path and returns the MAC (Modified, Accessed, Created) times to the user. One note is that this function will display the last accessed time and not he time the file was read by running the function. This function will work with both files and folders. It will then ask the user if they would like to search again, and loopback to main menu if not.

5) Malware Check: This function uses the VirusTotal API to scan files based off user input. The user will input what file they would like to scan and VirusTotal will return if there was any malware detected, along with scan date/time and the total number of engines used and how many of those detected malware. This will then prompt the user if they would like to scan again, and loopback to main menu if not.

6) Output to CSV: This function will ask the user for a directory they would like to get data from. Once this is input, the function takes the file name, file type, md5 hash, created time, modified time, accessed time, and malware status and outputs it to a file named "file_info.csv" to the users Desktop. The csv file is neatly formatted with all of the information on each file in the directory given.

7) Check for Compressed files: This function will check a file/directory for any signs of file compression. This will work on individual files as well as directories. If given a directory, the script will print out each file in that directory and let the user know if it is compressed or not. The files that are compressed will display a "***HIT***" tag before the user. It will then show the size of the file.

#Contribute
Feel free to contribute and make this script offer more functionality!

I plan on adding to this script actively, as I want it to be the most powerful tool it can be. There are certainly other functions that could be added to assist with any defensive capabilites. In the meantime, thank you for using this script and I hope it helps!
