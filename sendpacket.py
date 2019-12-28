from scapy.all import *
from scapy.layers.inet import TCP, IP


def pack_callback(packet):
  tcphead = packet[TCP]
  tcpOptionsfield = tcphead.options
  if len(tcpOptionsfield) == 0:
      return
  else:
      #获取数据包的TCPOPTIONS长度
      print(len(tcpOptionsfield))
      i = 0
      for i in range(len(tcpOptionsfield)):
          #获取TCPOPTIONS字段内的内容
          options = tcpOptionsfield[i]
          for j in range(len(options)):
              if options[j] == 'Experiment':
                  #获取最终目的地址
                  dst_addr = options[j]
                  print(dst_addr)

  #根据最终要到达的目的地址决定下一跳主机，并把下一跳主机地址替换至此包的目的地址
  next_addr = "215" #转换地址
  iphead = packet[IP]
  iphead.dst = next_addr
  send(packet)#转发给下一跳主机节点


# prn=pack_callback,
filterstr="tcp"#过滤
sniff(filter=filterstr, prn=pack_callback)