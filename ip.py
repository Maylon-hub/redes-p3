from iputils import *
import struct
import ipaddress


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = None
    
    
    def handle_time_exceeded_and_send(self, src_addr, datagrama):
        next_hop = self._next_hop(src_addr)
        
        total_len = 48  
        ttl = 64
        proto = IPPROTO_ICMP
        
        cabecalho_ip = self.criaHeader(total_len, ttl, proto, self.meu_endereco, src_addr)
        
        icmp_type = 11  
        icmp_code = 0   
        icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, 0, 0)
        
        rest_of_datagram = datagrama[:28]  
        checksum = calc_checksum(icmp_header + rest_of_datagram)
        
        icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, 0, 0)
        
        self.enlace.enviar(cabecalho_ip + icmp_header + rest_of_datagram, next_hop)



    def criaHeader(self, total_len, ttl, proto, src_addr, dst_addr, checksum=0):

        src_addr = int(ipaddress.IPv4Address(src_addr))
        dst_addr = int(ipaddress.IPv4Address(dst_addr))

        cabecalho = struct.pack(
            '!BBHHHBBHII',
            (4 << 4) + 5, 0, total_len, 0, 0,
            ttl, proto, checksum, src_addr, dst_addr
        )
        
        if checksum == 0:
            checksum = calc_checksum(cabecalho)
            cabecalho = struct.pack(
                '!BBHHHBBHII',
                (4 << 4) + 5, 0, total_len, 0, 0,
                ttl, proto, checksum, src_addr, dst_addr
            )
        
        return cabecalho


    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
        src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            next_hop = self._next_hop(dst_addr)

            ttl += -1
            
            if ttl == 0:
                self.handle_time_exceeded_and_send(src_addr, datagrama)
                return
            
            cabecalho = self.criaHeader(20 + len(datagrama), ttl, proto, src_addr, dst_addr)
            datagrama = cabecalho + payload
            
            self.enlace.enviar(datagrama, next_hop)


    def _next_hop(self, dest_addr):

        dest = ipaddress.ip_address(dest_addr)
        matches = [
            (ipaddress.ip_network(cidr).prefixlen, next_hop)
            for cidr, next_hop in self.tabela
                if dest in ipaddress.ip_network(cidr)
        ]
        
        return max(matches, key=lambda x: x[0])[1] if matches else None


    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        next_hop = self._next_hop(dest_addr)


        total_len = 20 + len(segmento)
        cabecalho = self.criaHeader(total_len, 64, 6, self.meu_endereco, dest_addr)
        datagrama = cabecalho + segmento
        
        self.enlace.enviar(datagrama, next_hop)
