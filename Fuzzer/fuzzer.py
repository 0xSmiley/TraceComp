import json
import docker
import os 

client = docker.from_env()

with open('conf.json') as json_file:
    data = json.load(json_file)
    for line in data['fuzz']:
        container=line['container']
        args=line['command']
        if 'mounthost' in line:
            hostMount=line['mounthost']
            containerMount=line['mountContainer']
            vols={hostMount: {'bind': containerMount}}
            client.containers.run(container, args,network='host',volumes=vols)
        else :
            client.containers.run(container, args,network='host')