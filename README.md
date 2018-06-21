# 3IP

用Python查询纯真IP库

QQWry.Dat的格式如下:

+----------+

|  文件头  |  (8字节)

+----------+

|  记录区  | （不定长）

+----------+

|  索引区  | （大小由文件头决定）

+----------+


文件头：4字节开始索引偏移值+4字节结尾索引偏移值

记录区： 每条IP记录格式：IP地址[国家信息][地区信息]

   对于国家记录，可以有三种表示方式：

       字符串形式(IP记录第5字节不等于0x01和0x02的情况)，
       重定向模式1(第5字节为0x01),则接下来3字节为国家和地区信息存储地的偏移值
       重定向模式2(第5字节为0x02),则接下来3字节为国家信息存储地的偏移值

   对于地区记录，可以有两种表示方式： 字符串形式和重定向

索引区： 每条索引记录格式：4字节起始IP地址 + 3字节指向IP记录的偏移值

   索引区的IP和它指向的记录区一条记录中的IP构成一个IP范围。查询信息是这个
   范围内IP的信息


用法：

1.命令行查询

	./ip.py 1.1.1.1		查询IP归属
	./ip.py 100-200		查询编号100-200的IP记录

2.Web浏览器查询

	http://xxx/ip?a=1.1.1.1		查询IP归属
	http://xxx/ip?a=100-200		查询编号100-200的IP记录
	http://xxx/ip?a=1.1.1.1&j=1	返回json格式

  http服务配置uwsgi支持，以nginx举例：
	location /ip {
                allow all;
                include uwsgi_params;
                uwsgi_pass 127.0.0.1:9009;
        }

  uwsgi配置：
	[uwsgi]
	  chdir=/path/to/program
	  master=True
	  pidfile=/run/uwsgi/ip.pid
	  logto=/var/log/uwsgi/ip.log
	  vacuum=True
	  max-requests=1000
	  threads=2
	  processes=1
	  socket = 127.0.0.1:9009
	  uid = uwsgi
	  gid = uwsgi
	  plugins = python
	  buffer-size=32768
	  wsgi-file=ip.py
	  touch-reload=ip.py

