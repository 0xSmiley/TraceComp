docker run -it --rm \
  --privileged \
  -v /lib/modules:/lib/modules \
  -v /usr/src:/usr/src \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc/localtime:/etc/localtime \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /home/ubuntu/Desktop/Share/Runtime/Tracer:/tracer \
  -e HOST_HOSTNAME=`hostname` \
  --workdir /tracer \
  nunolopes97/container_trace
