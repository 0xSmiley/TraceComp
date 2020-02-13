docker run -it --rm \
  --privileged \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /etc/localtime:/etc/localtime:ro \
  -v /home/ubuntu/Desktop/Share/Runtime/Tracer:/tracer \
  -e HOST_HOSTNAME=`hostname` \
  --workdir /usr/share/bcc/tools \
  zlim/bcc