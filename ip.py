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
    #Passo 4
    def montar_cabecalho(self, total_len, ttl, proto, src_addr, dst_addr):
        """
        Monta o cabeçalho IP com os valores fornecidos.
        """
        src_addr = int(ipaddress.IPv4Address(src_addr))
        dst_addr = int(ipaddress.IPv4Address(dst_addr))
        
        cabecalho = struct.pack(
            '!BBHHHBBHII',
            (4 << 4) + 5, 0, total_len, 0, 0,
            ttl, proto, 0, src_addr, dst_addr
        )
        
        checksum = calc_checksum(cabecalho)
        
        cabecalho = struct.pack(
            '!BBHHHBBHII',
            (4 << 4) + 5, 0, total_len, 0, 0,
            ttl, proto, checksum, src_addr, dst_addr
        )
        
        return cabecalho

    def __raw_recv(self, datagrama):
        """
        Função interna que processa os datagramas recebidos.
        """
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
        src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            # Atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # Atua como roteador
            next_hop = self._next_hop(dst_addr)

            #Passo 4
            ttl -= 1
            
            #Passo 5
            if ttl == 0:
                self._handle_time_exceeded(src_addr, datagrama)
                return
    
            cabecalho = self.montar_cabecalho(20 + len(datagrama), ttl, proto, src_addr, dst_addr)
            datagrama = cabecalho + payload
            
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        """
        Determina o próximo salto (next_hop) para o endereço de destino fornecido.
        """

        #Passo 1
        dest = ipaddress.ip_address(dest_addr)
        matches = [
            (ipaddress.ip_network(cidr).prefixlen, next_hop)
            for cidr, next_hop in self.tabela
                # Passo 3
                if dest in ipaddress.ip_network(cidr)
        ]
        
        return max(matches, key=lambda x: x[0])[1] if matches else None

    def _handle_time_exceeded(self, src_addr, datagrama):
        """
        Lida com a situação em que o TTL de um datagrama atinge 0.
        """
        next_hop = self._next_hop(src_addr)
        cabecalho_ip = self.montar_cabecalho(48, 64, IPPROTO_ICMP, self.meu_endereco, src_addr)
        
        type, code, unused = 11, 0, 0
        rest = datagrama[:28]
        cabecalho_icmp = struct.pack('!BBHHH', type, code, 0, unused, 0)
        checksum = calc_checksum(cabecalho_icmp + cabecalho_ip)
        
        cabecalho_icmp = struct.pack('!BBHHH', type, code, checksum, unused, 0)
        self.enlace.enviar(cabecalho_ip + cabecalho_icmp + rest, next_hop)

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 deste host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato [(cidr, next_hop), ...].
        """
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede.
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia um segmento para dest_addr (endereço IPv4).
        """
        next_hop = self._next_hop(dest_addr)

        #Passo 2

        total_len = 20 + len(segmento)
        cabecalho = self.montar_cabecalho(total_len, 64, 6, self.meu_endereco, dest_addr)
        datagrama = cabecalho + segmento
        
        self.enlace.enviar(datagrama, next_hop)
