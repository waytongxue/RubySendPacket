RubySendPacket
==============

ruby进行构造数据包, 从指定网卡发出去.  未完成, todo...


#定义包结构
eth = RSP::Ethernet.new('ff-ff-ff-ff-ff-ff','00-00-00-00-22-01')
ip = RSP::IP.new('0.0.0.0','255.255.255.255')
udp = RSP::UDP.new(68,67)
data = RSP::Data.new('c:/wdw.dat')   #数据包二进制字符串(raw data),使用wireshark选中数据部分,右键保存


#应用层没有定义格式, 只定义了一个简单的dhcp格式.  大家可以扩展七层协议.
dhcp = RSP::DHRSP.new(mac,'discover')
dhcp.add_opt(53,[1])  #dhcp 消息类型
dhcp.add_opt(61,[1].pack('C')+RSP::Utils.mac2byte(eth.src))  #客户端标识
dhcp.add_opt(12,'way')  #主机名
dhcp.add_opt(60,'MSFT 6.0')  #厂商标识

#组装包并发送
pkt = RSP::Packet.new('本地连接')
pkt.l2 = eth
pkt.vlan = xxxx
pkt.l3 = ip
pkt.l4 = udp
pkt.l7 = dhcp
pkt.send    #默认会计算数据包长度, 自动计算ip和udp/tcp校验和, 然后从指定网卡发出去
pkt.send({:l3_checksum=false})   #发送不计算ip检验和的数据包

pkt.pkt  #默认会计算数据包长度, 自动计算ip和udp/tcp校验和
pkt.pkt({:l3_checksum=false})  #意思就是不计算3层(ip)检验和
参考: {:l3_checksum => true,:l4_checksum => true,:l2_type=>true,:l3_protocol=>true,:l3_length=>true,:l4_length=>true}
pkt.raw  #不会计算任何检验和及长度, 完全是自己定义的原始数据包, 目的用来构造异常数据包

RSP::Packet.send_packet(pkt.raw,'本地连接')   #另外一种发包方法