import json
import os

with open('conf.json') as json_file:
    data = json.load(json_file)
    for line in data['fuzz-url']:
        contaienr=line['container']
        args=line['command']
        os.system("docker run --rm "+ contaienr+" "+ args)
        
        