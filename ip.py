#!/usr/bin/env python
# coding: utf-8

'''用Python查询纯真IP库

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

'''

'''
IPv6wry.DB格式:
文件头
0~3	字符串	"IPDB"
4~5	short	版本号,现在是2
6	byte	偏移地址长度(2~8)
7	byte	IP地址长度(4或8或12或16, 现在只支持4(ipv4)和8(ipv6))
8~15	int64	记录数
16~23	int64	索引区第一条记录的偏移
24	byte	地址字段数(1~255)[版本2新增,版本1是2]
25~31	reserve	保留,用00填充
记录区
array 字符串[地址字段数]
	与qqwry.dat大致相同,但是没有结束IP地址
	01开头的废弃不用
	02+偏移地址[偏移长度]表示重定向
	20~FF开头的为正常的字符串,采用UTF-8编码,00结尾
索引区
struct{
	IP[IP地址长度]	little endian, 开始IP地址
	偏移[偏移长度]	little endian, 记录偏移地址
}索引[记录数];
'''

import sys, socket, time, re, ipaddr
from struct import pack, unpack, unpack_from
from urlparse import parse_qs

class IPInfo(object):
    '''QQWry.Dat数据库查询功能集合
    '''
    def __init__(self, dbname):
        ''' 初始化类，读取数据库内容为一个字符串，
        通过开始8字节确定数据库的索引信息'''

        self.dbname = dbname
        f = file(dbname, 'r')
        self.img = f.read()
        f.close()

        # QQWry.Dat文件的开始8字节是索引信息,前4字节是开始索引的偏移值，
        # 后4字节是结束索引的偏移值。
        (self.firstIndex, self.lastIndex) = unpack('II', self.img[:8])
        # 每条索引长7字节，这里得到索引总个数
        self.indexCount = (self.lastIndex - self.firstIndex) / 7 + 1

    def getString(self, offset = 0):
        ''' 读取字符串信息，包括"国家"信息和"地区"信息

        QQWry.Dat的记录区每条信息都是一个以'\0'结尾的字符串'''

        o2 = self.img.find('\0', offset)
        #return self.img[offset:o2]
        # 有可能只有国家信息没有地区信息，
        gb2312_str = self.img[offset:o2]
        try:
            utf8_str = unicode(gb2312_str,'gb2312').encode('utf-8')
        except:
            return '未知'
        return utf8_str

    def getLong3(self, offset = 0):
        '''QQWry.Dat中的偏移记录都是3字节，本函数取得3字节的偏移量的常规表示
        QQWry.Dat使用“字符串“存储这些值'''
        s = self.img[offset: offset + 3]
        s += '\0'
        # unpack用一个'I'作为format，后面的字符串必须是4字节
        return unpack('I', s)[0]

    def getAreaAddr(self, offset = 0):
        ''' 通过给出偏移值，取得区域信息字符串，'''

        byte = ord(self.img[offset])
	#print 'getAreaAddr:%d' % byte
        if byte == 1 or byte == 2:
            # 第一个字节为1或者2时，取得2-4字节作为一个偏移量调用自己
            p = self.getLong3(offset + 1)
            return self.getAreaAddr(p)
        else:
            return self.getString(offset)

    def getAddr(self, offset, ip = 0):
        img = self.img
        o = offset
        byte = ord(img[o])

	#print 'getAddr:%d' % byte

        if byte == 1:
            # 重定向模式1
            # [IP][0x01][国家和地区信息的绝对偏移地址]
            # 使用接下来的3字节作为偏移量调用字节取得信息
            return self.getAddr(self.getLong3(o + 1))

        if byte == 2:
            # 重定向模式2
            # [IP][0x02][国家信息的绝对偏移][地区信息字符串]
            # 使用国家信息偏移量调用自己取得字符串信息
            cArea = self.getAreaAddr(self.getLong3(o + 1))
            o += 4
            # 跳过前4字节取字符串作为地区信息
            aArea = self.getAreaAddr(o)
            return cArea, aArea

        if byte != 1 and byte != 2:
            # 最简单的IP记录形式，[IP][国家信息][地区信息]
            # 重定向模式1有种情况就是偏移量指向包含国家和地区信息两个字符串
            # 即偏移量指向的第一个字节不是1或2,就使用这里的分支
            # 简单地说：取连续取两个字符串！

            cArea = self.getString(o)
            #o += len(cArea) + 1
            # 我们已经修改cArea为utf-8字符编码了，len取得的长度会有变，
            # 用下面方法得到offset
            o = self.img.find('\0',o) + 1
	    byte = ord(img[o])

	    if byte == 2:
            	aArea = self.getAreaAddr(o)
	    else:
            	aArea = self.getString(o)

            return cArea, aArea

    def find(self, ip, l, r):
        ''' 使用二分法查找网络字节编码的IP地址的索引记录'''
        if r - l <= 1:
            return l

        m = (l + r) / 2
        o = self.firstIndex + m * 7
        new_ip = unpack('I', self.img[o: o+4])[0]
        if ip == new_ip:
	    return m
        if ip < new_ip:
            return self.find(ip, l, m)
        else:
            return self.find(ip, m, r)

    def getIPAddr(self, ip):
        ''' 调用其他函数，取得信息！'''
        # 使用网络字节编码IP地址
        ip = unpack('!I', socket.inet_aton(ip))[0]
        # 使用 self.find 函数查找ip的索引偏移
        i = self.find(ip, 0, self.indexCount - 1)
        # 得到索引记录
        o = self.firstIndex + i * 7
        # 索引记录格式是： 前4字节IP信息+3字节指向IP记录信息的偏移量
        # 这里就是使用后3字节作为偏移量得到其常规表示（QQWry.Dat用字符串表示值）
        o2 = self.getLong3(o + 4)
        # IP记录偏移值+4可以丢弃前4字节的IP地址信息。
        (c, a) = self.getAddr(o2 + 4)
        return c, a

    def output(self, first, last):
	#walk through the ip db
        for i in range(first, last):
            o = self.firstIndex +  i * 7
            ip = socket.inet_ntoa(pack('!I', unpack('I', self.img[o:o+4])[0]))
            offset = self.getLong3(o + 4)
            (c, a) = self.getAddr(offset + 4)
	    if a == ' CZ88.NET':
		a = ''
            print "%s %d %s %s" % (ip, offset, c, a)

    def outputS(self, first, last, json=False):
	#walk through the ip db
	if json == True:
		s = '{"ip":"offset cArea aArea"'
	else:
		s = ''

        for i in range(first, last):
            o = self.firstIndex +  i * 7
            ip = socket.inet_ntoa(pack('!I', unpack('I', self.img[o:o+4])[0]))
            offset = self.getLong3(o + 4)
            (c, a) = self.getAddr(offset + 4)
	    if a == ' CZ88.NET':
		a = ''

	    if json == True:
            	s = s + ',"%s":"%s %s %s"' % (ip, offset, c, a)
	    else:
            	s = s + "%s %d %s %s\n" % (ip, offset, c, a)

	if json == True:
		s = s + '}'

	return s

def inet_ntoa(number):
	addresslist=[]
	addresslist.append((number>>24)&0xff)
	addresslist.append((number>>16)&0xff)
	addresslist.append((number>>8)&0xff)
	addresslist.append(number&0xff)
	return ".".join("%d" % i for i in addresslist)

def inet_ntoa6(number):
	addresslist=[]
	addresslist.append((number>>48)&0xffff)
	addresslist.append((number>>32)&0xffff)
	addresslist.append((number>>16)&0xffff)
	addresslist.append(number&0xffff)
	return ":".join("%04X" % i for i in addresslist) + "::"

class IPDBv6(object):
	"""ipv6wry.db数据库查询功能集合
	refer to https://github.com/Rhilip/ipv6wry.db/blob/master/parser/python/ipdbv6.py
	"""
	def __init__(self, dbname = "ipv6wry.db"):
		""" 初始化类，读取数据库内容为一个字符串
		"""
	
		self.dbname = dbname
		f = file(dbname, "rb")
		self.img = f.read()
		f.close()

		if self.img[:4] != "IPDB":
			# 数据库格式错误
			return
		if self.getLong8(4, 2) > 1:
			# 数据库格式错误
			return
		self.firstIndex = self.getLong8(16)
		self.indexCount = self.getLong8(8)
		self.offlen = self.getLong8(6, 1)
	
	def getString(self, offset = 0):
		""" 读取字符串信息，包括"国家"信息和"地区"信息

		QQWry.Dat的记录区每条信息都是一个以"\0"结尾的字符串"""
		
		o2 = self.img.find("\0", offset)
		# 有可能只有国家信息没有地区信息，
		gb_str = self.img[offset:o2]
		try:
			utf8_str = unicode(gb_str,"utf-8")
		except:
			return u"未知数据"
		return utf8_str

	def getLong8(self, offset = 0, size = 8):
		s = self.img[offset: offset + size]
		s += "\0\0\0\0\0\0\0\0"
		return unpack_from("Q", s)[0]

	def getAreaAddr(self, offset = 0):
		""" 通过给出偏移值，取得区域信息字符串，"""
		
		byte = ord(self.img[offset])
		if byte == 1 or byte == 2:
			# 第一个字节为1或者2时，取得2-4字节作为一个偏移量调用自己
			p = self.getLong8(offset + 1, self.offlen)
			return self.getAreaAddr(p)
		else:
			return self.getString(offset)

	def getAddr(self, offset, ip = 0):
		img = self.img
		o = offset
		byte = ord(img[o])

		if byte == 1:
			# 重定向模式1
			# [IP][0x01][国家和地区信息的绝对偏移地址]
			# 使用接下来的3字节作为偏移量调用字节取得信息
			return self.getAddr(self.getLong8(o + 1, self.offlen))

		else:
			# 重定向模式2 + 正常模式
			# [IP][0x02][信息的绝对偏移][...]
			cArea = self.getAreaAddr(o)
			if byte == 2:
				o += 1 + self.offlen
			else:
				o = self.img.find("\0",o) + 1
			aArea = self.getAreaAddr(o)
			return (cArea, aArea)

	def find(self, ip, l, r):
		""" 使用二分法查找网络字节编码的IP地址的索引记录"""
		if r - l <= 1:
			return l

		m = (l + r) / 2
		o = self.firstIndex + m * (8 + self.offlen)
		new_ip = self.getLong8(o)
		if ip < new_ip:
			return self.find(ip, l, m)
		else:
			return self.find(ip, m, r)
		
	def getIPAddr(self, ip, i4obj = None):
		""" 调用其他函数，取得信息！"""
		try:
			# 把IP地址转成数字
			ip6 = int(ipaddr.IPAddress(ip))
			ip = (ip6 >> 64) & 0xFFFFFFFFFFFFFFFF
			# 使用 self.find 函数查找ip的索引偏移
			i = self.find(ip, 0, self.indexCount)
			# 得到索引记录
			o = self.firstIndex + i * (8 + self.offlen)
			o2 = self.getLong8(o + 8, self.offlen)
			(c, a) = self.getAddr(o2)
			(cc, aa) = (c, a)
			i1 = inet_ntoa6(self.getLong8(o))
			try:
				i2 = inet_ntoa6(self.getLong8(o + 8 + self.offlen) - 1)
			except:
				i2 = "FFFF:FFFF:FFFF:FFFF::"
			if ip6 == 0x1:					# 本机地址
				i1 = "0:0:0:0:0:0:0:1"
				i2 = "0:0:0:0:0:0:0:1"
				c = cc = u"本机地址"
			elif ip == 0 and ip6 >> 32 & 0xFFFFFFFF == 0xFFFF:	# IPv4映射地址
				realip = (ip6 & 0xFFFFFFFF)
				realipstr = inet_ntoa(realip)
				try:
					(_, _, realiploc, cc, aa) = i4obj.getIPAddr(realip)
				except:
					realiploc = NO_IPV4_DB
				i1 = "0:0:0:0:0:FFFF:0:0"
				i2 = "0:0:0:0:0:FFFF:FFFF:FFFF"
				c = u"IPv4映射地址"
				a = a + u"<br/>对应的IPv4地址为" + realipstr + u"，位置为" + realiploc
			elif ip >> 48 & 0xFFFF == 0x2002:		# 6to4
				realip = (ip & 0x0000FFFFFFFF0000) >> 16
				realipstr = inet_ntoa(realip)
				try:
					(_, _, realiploc, cc, aa) = i4obj.getIPAddr(realip)
				except:
					realiploc = NO_IPV4_DB
				a = a + u"<br/>对应的IPv4地址为" + realipstr + u"，位置为" + realiploc
			elif ip >> 32 & 0xFFFFFFFF == 0x20010000:	# teredo
				serverip = (ip & 0xFFFFFFFF)
				serveripstr = inet_ntoa(serverip)
				realip = (~ip6 & 0xFFFFFFFF)
				realipstr = inet_ntoa(realip)
				try:
					(_, _, serveriploc, cc, aa) = i4obj.getIPAddr(serverip)
					(_, _, realiploc, _, _) = i4obj.getIPAddr(realip)
				except:
					serveriploc = NO_IPV4_DB
					realiploc = NO_IPV4_DB
				a = a + u"<br/>Teredo服务器的IPv4地址为" + serveripstr + u"，位置为" + serveriploc
				a = a + u"<br/>客户端真实的IPv4地址为" + realipstr + u"，位置为" + realiploc
			elif ip6 >> 32 & 0xFFFFFFFF == 0x5EFE:		# isatap
				realip = (ip6 & 0xFFFFFFFF)
				realipstr = inet_ntoa(realip)
				try:
					(_, _, realiploc, _, _) = i4obj.getIPAddr(realip)
				except:
					realiploc = NO_IPV4_DB
				a = a + u"<br/>ISATAP地址，对应的IPv4地址为" + realipstr + u"，位置为" + realiploc
		except:
			i1 = ""
			i2 = ""
			c = cc = u"错误的IP地址"
			a = aa = ""
		return (i1, i2, c + u" " + a, cc, aa)
		

ipcache = {}
i = IPInfo('qqwry.dat')
i6 = IPDBv6('ipv6wry.db')

def city_analyst(s, json=False):
    aa = []
    country = "中国"
    province = ""
    city = ""
    block = ""
    carrier = ""
    network = ""

    finish = False

    if s.find(country) == 0:
	s = s.replace(country, '', 1)
    
    #中国运营商
    if len(aa) == 0:
    	rs = r"(.+)省(.+)市(.+)区:(.+)"
    	res = re.compile(rs)
    	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		province = a[0]
		city = a[1]
		block = a[2]
		carrier = a[3]

    if len(aa) == 0:
	rs = r"(.+)省(.+)市:(.+)(公司)(.*)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		province = a[0]
		city = a[1]
		carrier = a[2]+a[3]
		network = a[4]

    if len(aa) == 0:
	rs = r"(.+)省(.+)市:(.*)(电信|移动|联通)(.*)"
	res = re.compile(rs)
	aa = res.findall(s)
	if len(aa) > 0:
		a = aa[0]
		province = a[0]
		city = a[1]
		carrier = a[2]+a[3]
		network = a[4]
			
    if len(aa) == 0:
	rs = r"(.+)省(.+)市:(.+)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		province = a[0]
		city = a[1]
		carrier = a[2]

    if len(aa) == 0:
	rs = r"(.+)省:(.+)(公众宽带)"
	res = re.compile(rs)
	aa = res.findall(s)
	if len(aa) > 0:
		a = aa[0]
		province = a[0]
		carrier = a[1]
		network = a[2]
			
    if len(aa) == 0:
	rs = r"(.+)省:(.+)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		province = a[0]
		carrier = a[1]

    #外国运营商
    if len(aa) == 0:
	rs = r"(.+):(.+)州(.+)县(.+)村(.+)(公司)(.*)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		country = a[0]
		province = a[1]
		city = a[2]
		block = a[3]
		carrier = a[4]+a[5]
		network = a[6]
	
    if len(aa) == 0:
	rs = r"(.+):(.+)州(.+)县(.+)市(.+)(公司)(.*)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		country = a[0]
		province = a[1]
		city = a[2]
		block = a[3]
		carrier = a[4]+a[5]
		network = a[6]
	
    if len(aa) == 0:
	rs = r"(.+):(.+)州(.+)县(.+)村(.+)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		country = a[0]
		province = a[1]
		city = a[2]
		block = a[3]
		carrier = a[4]
	
    if len(aa) == 0:
	rs = r"(.+):(.+)州(.+)县(.+)(公司)(.*)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		country = a[0]
		province = a[1]
		city = a[2]
		carrier = a[3]+a[4]
		network = a[5]

    if len(aa) == 0:
	rs = r"(.+):(.+)州(.+)市(.+)(公司)(.*)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		country = a[0]
		province = a[1]
		city = a[2]
		carrier = a[3]+a[4]
		network = a[5]

    if len(aa) == 0:
	rs = r"(.+):(.+)州(.+)市(.*)"
	res = re.compile(rs)
	aa = res.findall(s)
	if len(aa) > 0:
		a = aa[0]
		country = a[0]
		province = a[1]
		city = a[2]
		carrier = a[3]

    if len(aa) == 0:
	rs = r"(.+):(.+)(公司)(.*)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		country = a[0]
		carrier = a[1]+a[2]
		network = a[3]

    if len(aa) == 0:
	rs = r"(.+):(.+)州(.*)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		country = a[0]
		province = a[1]
		carrier = a[2]

    if len(aa) == 0:
	rs = r"(.+):(.+)"
	res = re.compile(rs)
	aa = res.findall(s)
    	if len(aa) > 0:
		a = aa[0]
		country = a[0]
		carrier = a[1]

    if country == "香港" or country == "澳门" or country == "台湾":
	province = country
	country = "中国"

    if carrier == ' CZ88.NET':
	carrier = ""

    if len(aa) > 0:
	if json == True:
    		return '{"国家":' + '"'+ country + '",' + '"省份":' + '"' + province + '",' + '"城市":' + '"' + city + '",' + '"区域":' + '"' + block + '",' + '"运营商":' + '"' + carrier + '",' + '"网络":' + '"' + network + '"}'
	else:
    		return "国家:" + country + "\n省份:" + province + "\n城市:" + city + "\n区域:" +  block + "\n运营商:" + carrier + "\n网络:" + network
    else:
	return ""

def application(environ, start_response):

    ts = time.time()

    js = parse_qs(environ['QUERY_STRING']).get('j', [None])[0]
    if js != None:
    	content_type = ('Content-Type', 'application/json; charset=utf-8')
	json = True
    else:
    	content_type = ('Content-Type', 'text/html; charset=utf-8')
	json = False

    ips = parse_qs(environ['QUERY_STRING']).get('a', [None])[0]

    try:
    	if ips == None:
		ips = environ['HTTP_X_FORWARDED_FOR']
    except:
	ips = None

    if ips == None:
	ips = environ['REMOTE_ADDR']

    if ips != None:

	_ips = ips.split(',')
	ips = _ips[len(_ips)-1].strip()

	if "-" in ips:
        	xy = ips.split("-")
		if json == True:
        		resp = i.outputS(int(xy[0]), int(xy[1]), json=True)
    			start_response('200 OK', [content_type, ('Content-Length', str(len(resp)))])
		else:
        		resp = '<pre>' + i.outputS(int(xy[0]), int(xy[1])) + '</pre>'
    			start_response('200 OK', [content_type, ('Content-Length', str(len(resp)))])

       		return resp

	if ":" in ips:
		is_ipv6 = True
	else:
		is_ipv6 = False
		

	if ips in ipcache:
		(c, a) = ipcache[ips]
	else:
	  try:
		if is_ipv6:
    			(_, _, _, _c, _a) = i6.getIPAddr(ips)
			(c, a) = (_c.encode("utf-8"), _a.encode("utf-8"))
		else:
    			(c, a) = i.getIPAddr(ips)
		if len(ipcache) >= 1000:
			ipcache.pop()
		ipcache[ips] = (c, a)
	  except:
		print ips

	if js != None:
    		resp = '{"ip":"%s", "cArea":"%s", "aArea":"%s", "time":"%s", "array":%s}' % (ips, c, a,
				str(time.time()-ts), city_analyst(c+":"+a, json=True))
	else:
    		resp = '<pre>%s %s %s<br><br>运行时间：%f 秒<br><br>%s</pre>' % (ips, c, a,
				time.time()-ts, city_analyst(c+":"+a))
    else:
	resp = '{"error": "no query param"}'

    resp += "<br><pre>\n----------------------------------------\nPowered by 3ip</pre>"
		
    start_response('200 OK', [content_type, ('Content-Length', str(len(resp)))])

    return  resp

def main():
    ts = time.time()

    if len(sys.argv) < 2:
	ips = "0.0.0.0"
    else:
	ips = sys.argv[1]

    if "-" in ips:
	xy = ips.split("-")
	i.output(int(xy[0]), int(xy[1]))
	return

    _ips = ips.split(',')
    ips = _ips[len(_ips)-1].strip()

    if ":" in ips:
	is_ipv6 = True
    else:
	is_ipv6 = False

    if ips in ipcache:
	(c, a) = ipcache[ips]
    else:
	if is_ipv6:
    		(_, _, _, _c, _a) = i6.getIPAddr(ips)
		(c, a) = (_c.encode("utf-8"), _a.encode("utf-8"))
	else:
    		(c, a) = i.getIPAddr(ips)
	ipcache[ips] = (c, a)

    print '%s %s %s %f秒' % (ips, c, a, time.time()-ts)
    print city_analyst(c+":"+a)
 
if __name__ == '__main__':
    main()
