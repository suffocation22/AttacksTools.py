#By suffocation22
#Date: 07.08.2022

import os
import platform
import time
import requests
import random
import socket
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

''''
The function InfoOS run the command ipconfig and print the IP address, OS type, version of OS, and the architecture of
the OS.
When it`s done, the function will ask the user if he wants to return to the main menu or not.
If he press 'no' it will stop running.
'''
def infoOS():
    os.system("ipconfig > ipconfig.txt")
    os_type = platform.system()
    versionOS = platform.version()
    archOS = platform.architecture()
    with open("ipconfig.txt", "r") as file:
        for line in file:
            if "IPv4" in line:
                ip = line.split(":")
        print(f"Your IP address is: {ip[-1]}\nYour OS type is: {os_type}\nYour version of your os is: {versionOS}\nThe "
              f"architecture of OS is: {archOS}")
    askUser = input("Are you want to back to Main Menu? please press Y / N: ")
    if askUser == "Y":
        print(menu())
    else:
        print("Ok, Thanks that you use in our function, Have a nice day =]")


''''
The function dirLis run commands like:ping, whoami and mkdir and print the result for each command.
You can to return to main menu when you press '0' on the keyboard
'''
def commanLine():
    while True:
        print("Welcome to command line, which command are you want:")
        print("[0] - main menu\n[1] - ping \n[2] - whoami \n[3] - mkdir\n")
        user_input = input("What you choose: ")
        if user_input == "0":
            print(menu())
        elif user_input == "1":
            ping = os.system("ping 8.8.8.8")
            print(f"You choose the command ping, the result is:\n {ping}")
        elif user_input == "2":
            whoAmI = os.system("whoami")
            print(f"You choose the command 'whoami', the result is:\n {whoAmI}")
        elif user_input == "3":
            os.mkdir(r"C:\Users\User\Desktop\new_folder")
            print(rf"You choose the command 'mkdir', the result is check the path 'C:\<Users\User>\Desktop':", '\n')
        else:
            print("something worn, bye bye")
            break


''''
The function dirLis will run the command 'os.getcwd' to check the current of the path you are on it.
Or if you press other it gives to a user all the directory path, directory name, and file name
The user can return to the main menu when you press 'Main Menu' or 'NO'
'''
def dirLis():
    while True:
        print("welcome to Directory listing")
        dirInput = input("which directory you want to check? CURRENT/OTHER/Main Menu:")
        if dirInput == "main menu":
            print(menu())
        elif dirInput == "current":
            print(os.getcwd())
        elif dirInput == "other":
            print(r"please insert a full path for check it: ")
            # dp = directory path, dn = directory name, fn = file name
            for dp, dn, fn in os.walk(os.getcwd()):
                print(f"path : {dp}")
                print(f"directories : {dn}")
                print(f"file : {fn}")
                print("=====================")
        elif dirInput == "NO":
            print(menu())
        else:
            print("Something worn, bye bye")
            break


''''
The function webHack runs the commands from the requests library like check if the website is alive if he gets '200' 
he will ask the user if he has a wordlist and check if the path is found or not.
If he gets like '4XX' or '5XX' he will print he can`t search any paths.
'''
def webHack():
    web_user = input("Which website do you want to: ")  # Get: http://hack-yourself-first.com/
    req = requests.get(web_user)
    webCheck = req.status_code
    print(f"Well I get your website is: {webCheck}")
    if webCheck == 200:
        askUser = input("Are you want to check which path are available? insert Y/N: ")
        if askUser == "Y":
            dictionary = input(
                "please enter your wordlist: ")  # the user put the path of his wordlist [C:/.../wordlist.txt]
            wordlist = open(dictionary, "r")
            for i in wordlist:
                req2 = requests.get(f"{web_user},{i}")
                time.sleep(3)
                if req2.status_code == 200:
                    print(f"The path {web_user}{i} is found")
                else:
                    print(f"Something wrong, I get {req2.status_code}")
        else:
            print("Well you are not hacker, bye bye")
    else:
        print(f"Well I get {webCheck}, please check your website and try again")


''''
The Port Scanner function gets the IP address and checks if the host is alive.
If the target is alive - the function asks the user for a file with a port list to check which port is open
If the port SSH is open, the function will be called the SSH brute force function.
If the port is closed the function will continue.
If the target is not alive then the function will return the user to the Menu
'''
def PortScanner(ipAddress):
    icmp = IP(dst=ipAddress) / ICMP()
    respICMP = sr1(icmp, timeout=10)
    if respICMP != None:
        print(f"We found the target {ipAddress} is up, let`s continue")
        portUser = input(f"Well for the IP address: {ipAddress} enter your ports list you want to check: ")  # get: C:\Users\User\Desktop\HACKERU\PYTHON\FinalProjectPython\PortLists.txt
        with open(portUser, "r") as port_list:
            for port in port_list:
                numRandom = random.randint(2, 5)
                port.strip("\n")
                try:
                    sock = socket.socket()
                    sock.connect((ipAddress, int(port)))
                    sock.send("testing\n".encode())
                    sock.settimeout(numRandom)
                    resp = sock.recv(2048).decode()
                    if resp != 0:
                        print(f"The port {port} is open.\nBanner is:\n{resp}")
                        if "SSH" in resp:
                            print(f"The function found the port: {port} is open.")
                            askUser = input(f"Are you want to connect that ip:{ipAddress} through SSH and make BF? enter Y/N: ")
                            if askUser == "Y":
                                print("We called to function SSH Brute Force, please wait and don`t hack us =]")
                            else:
                                break

                except ConnectionRefusedError:
                    print(f"The port {port} is closed")
                except socket.timeout:
                    print(f"The port {port} is timeout.")
    else:
        print(f"Well your target {ipAddress} is down, we bring you back to menu\n")
        print(menu())


def menu():
    print("Welcome To Interactive Shell")
    print(
        "[1] - System info \n[2] - Command line \n[3] - Directory listing\n[4] - Web crawler\n[5] - Port Scanner\n[6] - Exit")
    userInput = input("please select from the menu: ")

    if userInput == "1":
        print(infoOS())
    elif userInput == "2":
        print(commanLine())
    elif userInput == "3":
        print(dirLis())
    elif userInput == "4":
        print(webHack())
    elif userInput == "5":
        ip_choose = input("Enter the IP address for the scan ports: ")  # get: ip: 192.168.223.129
        print(PortScanner(ip_choose))
    elif userInput == "6":
        print("We hope you enjoy to use our code, have a great day =]")
    else:
        print("something worn, bye bye")


print(menu())
