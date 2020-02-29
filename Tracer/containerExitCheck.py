import grpc
import docker
from time import sleep
# import the generated classes
import service_pb2
import service_pb2_grpc
from concurrent import futures

# open a gRPC channel
channel = grpc.insecure_channel('localhost:50051')

# create a stub (client)
stub = service_pb2_grpc.ComunicationStub(channel)

client = docker.from_env()

class ComunicationServicer(service_pb2_grpc.ComunicationServicer):

    # calculator.square_root is exposed here
    # the request and response are of the data type
    # calculator_pb2.Number
    def AddUuts(self, request, context):
        response = service_pb2.Cofirmation()
        print("Waiting for "+request.uts+ "to exit")

        container = client.containers.get(request.uts)
        containerCheck=container.status.strip()
        while containerCheck!="exited":
            sleep(1)
            container = client.containers.get(request.uts)
            containerCheck=container.status.strip()
        
        response.confirm = 1
        return response


server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

# use the generated function `add_CalculatorServicer_to_server`
# to add the defined class to the server
service_pb2_grpc.add_ComunicationServicer_to_server(
        ComunicationServicer(), server)

# listen on port 50051
print('Starting gRPC service. Listening on port 50051.')
server.add_insecure_port('[::]:50051')
server.start()

try:
    while True:
        sleep(86400)
except KeyboardInterrupt:
    server.stop(0) 



