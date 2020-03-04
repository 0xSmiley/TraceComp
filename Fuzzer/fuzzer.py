import json
import docker
import os 

client = docker.from_env()

with open('conf.json') as json_file:
    data = json.load(json_file)
    for line in data['fuzz-url']:
        container=line['container']
        args=line['command']
        if 'inputs' in line:
            
            fullPath=line['inputs']
            temp = fullPath.split('/') 
            res = '/'.join(temp[:len(temp)-1]), '/'.join(temp[len(temp)-1:])
            path=res[0]
            mutateFile=res[1]

            os.system('docker run --rm -v '+path+':/Inputs nunolopes97/radamsa -r /Inputs/'+mutateFile+' -n 10 -o /Inputs/out%n.txt')
        #os.system("docker run --rm "+ container+" "+ args)
        
        