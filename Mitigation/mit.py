import argparse
import json
import colorama
import re

def main():

    parser = argparse.ArgumentParser(description='Tool to check vulnerable syscall in seccomp profile')
    parser.add_argument('-poc',  required=True,help='Path to Json Seccomp Profile represeting the Proof of Concept')
    parser.add_argument('-useC',  required=True,help='Path to Json Seccomp Profile represeting the Use Case')
    parser.add_argument('-all', help='Path to Json Seccomp Profile represeting all the Features')
    args = parser.parse_args()

    Poc=[]
    useC=[]
    All=[]
    try:
        with open(args.poc) as json_file:
            data = json.load(json_file)
            for line in data['syscalls']:
                for sys in line['names']:
                    Poc.append(sys)
    except:
        print("Error on -poc file")
    
    try:
        with open(args.useC) as json_file:
            data = json.load(json_file)
            for line in data['syscalls']:
                for sys in line['names']:
                    useC.append(sys)
    except:
        print("Error on -useC file")

    VulnSyscalls=[]
    VulnSyscalls=list(set(Poc) - set(useC))
    
    if len(VulnSyscalls)==0:
        print("All the syscalls in the PoC file are needed in the use case file.")
        return

    print("Vulnerable syscalls:")
    for syscall in VulnSyscalls:
        print('\t'+colorama.Fore.RED + syscall)
    
    if args.all is not None:
        try:
            with open(args.all, "r") as f:
                lines = f.readlines()
        except:
            print("Error on -all file")

        with open("newProfile.json","w") as f:
            for line in lines:
                tmp=re.findall(r"(?i)\b[a-z]+\b", line.strip())
                
                if "".join(tmp) not in VulnSyscalls:
                    f.write(line) 
                    
        print(colorama.Fore.GREEN + "A new profile has been generated")

if __name__== "__main__":
    main()
