require 'ffi/pcap'
require 'ipaddr'
require 'ruby-wmi'

#=========================================for example=============================================
#定义包结构
# eth = RSP::Ethernet.new('ff-ff-ff-ff-ff-ff','00-00-00-00-22-01')
# ip = RSP::IP.new('0.0.0.0','255.255.255.255')
# udp = RSP::UDP.new(68,67)
# data = RSP::Data.new('c:/wdw.dat')	 #数据包二进制字符串(raw data),使用wireshark选中数据部分,右键保存


#应用层没有定义格式, 只定义了一个简单的dhcp格式.  大家可以扩展七层协议.
# dhcp = RSP::DHRSP.new(mac,'discover')
# dhcp.add_opt(53,[1])	#dhcp 消息类型
# dhcp.add_opt(61,[1].pack('C')+RSP::Utils.mac2byte(eth.src))  #客户端标识
# dhcp.add_opt(12,'way')  #主机名
# dhcp.add_opt(60,'MSFT 6.0')  #厂商标识

#组装包并发送
# pkt = RSP::Packet.new('本地连接')
# pkt.l2 = eth
# pkt.vlan = xxxx
# pkt.l3 = ip
# pkt.l4 = udp
# pkt.l7 = dhcp
# pkt.send    #默认会计算数据包长度, 自动计算ip和udp/tcp校验和, 然后从指定网卡发出去
# pkt.send({:l3_checksum=false})   #发送不计算ip检验和的数据包

# pkt.pkt  #默认会计算数据包长度, 自动计算ip和udp/tcp校验和
# pkt.pkt({:l3_checksum=false})  #意思就是不计算3层(ip)检验和
# 参考: {:l3_checksum => true,:l4_checksum => true,:l2_type=>true,:l3_protocol=>true,:l3_length=>true,:l4_length=>true}
# pkt.raw  #不会计算任何检验和及长度, 完全是自己定义的原始数据包, 目的用来构造异常数据包

# RSP::Packet.send_packet(pkt.raw,'本地连接')		#另外一种发包方法



module RSP #the short name of Create Base
	class Error < RuntimeError; end
  # 协议报文长度错误
  class PktSizeError < Error; end
  # 数据包文件不存在
  class PktFileNoExistError < Error; end


	class Utils
		class << self
			def checksum(bytes)
				if bytes.size & 1 == 1
				    bytes = bytes + "\0"
				end 
				sum = 0
				bytes.unpack("n*").each {|n| sum += n }
				sum = (sum & 0xffff) + (sum >> 16 & 0xffff)
				~sum & 0xffff
			end

			def mac2byte(mac)
				case mac
				when /:/
					mac.split(':').inject(''){|m, b| m << b.to_i(16).chr}
				when /-/
					mac.split('-').inject(''){|m, b| m << b.to_i(16).chr}
				end
			end

			#devname to guid
			def name2guid(name)
				condition = {:conditions => {:net_connection_id => name}}
				eth = WMI::Win32_networkadapter.find(:first, condition)
				raise "interface name (#{name}) not exist !!!" if eth.nil?
				index = eth.index
				condition = {:conditions => {:index => index}}
				WMI::Win32_networkadapterconfiguration.find(:first, condition).setting_id
			end

		end
	end

	# ethernet, ip/ipv6, udp/tcp, data
	class Base
		PROTO_IP  = 0x0800
		PROTO_IPV6 = 0x86dd
		PROTO_VLAN = 0X8100
		PROTO_TRSP = 6
    PROTO_UDP = 17

		def size
			pkt.size
		end
	end

	class Ethernet < Base
		attr_accessor :src, :dst, :type
		def initialize(dst='00-00-00-00-00-00',src='00-00-00-00-00-00',type=PROTO_IP)
			@src ,@dst, @type = src,dst,type
		end

		def pkt
			[Utils.mac2byte(@dst), Utils.mac2byte(@src), [@type].pack('n')].join('')
		end

	end

	class Vlan < Base
		attr_accessor :vid, :type
		def initialize(vid=0x0001,type=PROTO_IP)
			@vid = vid
			@type = type
		end

		def pkt
			[@vid,@type].pack('nn')
		end

		def ptype
			PROTO_VLAN
		end
	end

	class IP < Base

    FMT = 'CCnnnCCna4a4'

		attr_accessor :vh,:tos,:length,:id,:offset,:ttl,:protocol,:checksum,:src,:dst
		def initialize(src='0.0.0.0',dst='0.0.0.0')
			@vh = 0x45
			@tos = 0x00
			@length = 0x0000
			@id = 0x0001
			@offset = 0x0000
			@ttl = 0x40
			@protocol = PROTO_UDP
			@checksum = 0
			@src = src
			@dst = dst
		end

		def src_hton
			IPAddr.new(@src).hton
		end

		def dst_hton
			IPAddr.new(@dst).hton
		end

		def calc_checksum
			@checksum = Utils.checksum([@vh, @tos, @length, @id, @offset, @ttl, @protocol, 0, src_hton, dst_hton].pack(FMT))
		end

		def pkt
			[@vh, @tos, @length, @id, @offset, @ttl, @protocol, @checksum, src_hton, dst_hton].pack(FMT)
		end

		def ptype
			PROTO_IP
		end

	end

	class IPV6 < Base
		# todo
		def pkt
		end

		def ptype
			PROTO_IPV6
		end
	end

	class UDP < Base
		attr_accessor :src, :dst, :length, :checksum
		FMT = 'nnnn'
		CHECKSUM_FMT = 'a4a4CCnnnnn'

		def initialize(src=0,dst=0)
			@src = src.to_i
			@dst = dst.to_i
			@length = 0
			@checksum = 0

			raise(Error,'port value is error! must be in 0-65535') unless (0..65535).include?(@src) && (0..65535).include?(@dst)
		end

		def calc_checksum(ip,data=nil)
			#   udp伪首部 + udp头部 + 数据包部分 , 三个部分加在一起作为计算源
			#1. udp伪首部: srcip + dstip + 0x00 + protocol + udp长度(包括数据部分)
			#2. udp头部: srcport + dstport +  udp长度(包括数据部分)
			#3  数据部分: 整个udp的数据包部分

			bytes = [ip.src_hton,ip.dst_hton,0x00,ip.protocol,@length,@src,@dst,@length,0x0000].pack(CHECKSUM_FMT)
			bytes += data.pkt if data
			@checksum = Utils.checksum(bytes)
		end

		def pkt
			[@src,@dst,@length,@checksum].pack(FMT)
		end

		def ptype
			PROTO_UDP
		end
	end

	class TRSP < Base
		CHECKSUM_FMT = 'a4a4CCn' + 'nn'

		attr_accessor :src,:dst,:sequence_number,:ack_number,:length,:flags,:windows_size,:checksum,:urgent_point
		def initialize(src=0,dst=0)
			@src = src
			@dst = dst
			@sequence_number = 0x0001
			@ack_number = 0x0000
			@length = 20
			@flags = 0x02    #syn
			@windows_size = 0x2000
			@checksum = 0x0000
			@urgent_point = 0x0000
		end

		def calc_checksum(ip,data=nil)
			#   tcp伪首部 + tcp头部 + 数据包部分 , 三个部分加在一起作为计算源
			#1. tcp伪首部: srcip + dstip + 0x00 + protocol + tcp长度(包括数据部分)
			#2. tcp头部: srcport + dstport +  tcp长度(包括数据部分)
			#3  数据部分: 整个udp的数据包部分

			bytes = [ip.src_hton,ip.dst_hton,0x00,ip.protocol,@length,@src,@dst,@sequence_number,@ack_number,@length,@flags,@windows_size,0x0000,@urgent_point].pack(CHECKSUM_FMT)
			bytes += data.pkt if data
			@checksum = Utils.checksum(bytes)
		end

		def pkt
		end

		def ptype
			PROTO_TRSP
		end
	end

	class Data < Base

		def initialize(file)
			raise PktFileNoExistError unless File.exist?(file)

			@pkt = ''
			case File.extname(file)
			when /dat/
				File.open(file,'rb') {|f| @pkt += f.read(65535) until f.eof? }
			when /pcap|cap/
				#pcap的数据包, 这里默认只取第一个数据包
				offline = FFI::PCap::Offline.new(file)
				# todo
			end

		end

		def pkt
			@pkt
		end

	end

	class DHRSP < Base
		#DHRSP two part of : bootp + dhcp option  

		def initialize(cmac='00-00-00-00-00-01',type='discover')
			@opt = []
			@cmac = cmac
			@type = type
		end

		def add_opt(code,value)
			case value.class.to_s
			when 'String'
				@opt << [code,value.size].pack('C*')
				@opt << value
			when 'Array'
				value.unshift(code,value.size)
				@opt << value.pack('C*')
			end

		end

		def bootp
			case @type
			when 'discover'
				[1,1,6,0,1,0,0].pack('CCCCNnn') + (IPAddr.new('0.0.0.0').hton)*4 + Utils.mac2byte(@cmac) + "\0"*(10+64+128)
			when 'request'
				# todo
			end
		end

		def dhcp_opt
			tmp = [1669485411].pack('N') + @opt.join('') + [255].pack('C')
			tmp += "\0"*(64-tmp.size >= 0 ? 64-tmp.size : 0)
		end

		def pkt
			bootp + dhcp_opt
		end

	end

	#assemble packet
	class Packet

		attr_accessor :l2,:l23,:l3,:l4,:l7
		def initialize(devname=nil)
			if devname
				dev = '\Device\NPF_'+Utils.name2guid(devname)
			else
				dev = FFI::PCap.dump_devices[0][0]
			end
			puts "choise interface:(#{devname}) " + dev
			@live = FFI::PCap::Live.new(:device => dev,:handler => FFI::PCap::Handler, :promisc => true)
		end

		def raw
			bytes = ''
			[@l2,@l23,@l3,@l4,@l7].each do |obj|
				bytes += obj.pkt if obj
			end

			return bytes 
		end

		def pkt(pkt_hash={})
			
			hash={:l3_checksum => true,:l4_checksum => true,:l2_type=>true,:l3_protocol=>true,:l3_length=>true,:l4_length=>true}
			hash.merge!(pkt_hash)

			# 1. eth type and ip protocol
			@l2.type = @l23 ? @l23.ptype : @l3.ptype
			@l23.type = @l3.ptype if @l23
			@l3.protocol = @l4.ptype

			# 2. calculate ip length and udp length
			@l3.length = @l3.size + @l4.size + @l7.size 	if hash[:l3_length]
			@l4.length = @l4.size + @l7.size 	if hash[:l4_length]

			# 3. calculate ip checksum and udp checksum; 
			@l3.calc_checksum if hash[:l3_checksum]
			@l4.calc_checksum(@l3,@l7) if hash[:l4_checksum]

			# 4. assemble packet
			bytes = ''
			[@l2,@l23,@l3,@l4,@l7].each do |obj|
				bytes += obj.pkt if obj
			end

			return bytes 

		end

		def send(hash={})
			@live.send_packet(pkt(hash))
		end

		def self.send_packet(pkt_str,devname=nil)
			if devname
				dev = '\Device\NPF_'+Utils.name2guid(devname)
			else
				dev = FFI::PCap.dump_devices[0][0]
			end
			puts "choise interface:(#{ifname}) " + dev
			@live = FFI::PCap::Live.new(:device => dev,:handler => FFI::PCap::Handler, :promisc => true)
			live.send_packet pkt_str
		end

	end



end #end of module pcap


