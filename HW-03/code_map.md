# HW3 code map

1. Захват всех DNS пакетов и вывод на консоль
   - main.go: регистрация команды sniff и стартовый help
   - internal/commands/sniff.go: NewSniffCommand, Run, formatDNSPacket
   - internal/packet/packet.go: ParseEthernetFrame, ParseIPv4Packet, ParseUDPDatagram, ParseTCPHeader
   - internal/dns/message.go: ParseMessage

2. Поиск MX и IPmx для домена
   - internal/commands/mx.go: NewMXCommand, Run
   - internal/dns/client.go: ExchangeRawUDP, CollectMXRecords, CollectARecords
   - internal/dns/message.go: NewQuery, ParseMessage
   - internal/packet/packet.go: MarshalBinary для Ethernet/IPv4/UDP
   - internal/arp/frame.go: ResolveIPv4
   - internal/sysinfo/netinfo.go: NextHopIPv4, DetectProviderDNSIPv4ForInterface

3. Сравнение ответов root DNS и DNS провайдера
   - internal/commands/compare.go: NewCompareCommand, Run, runScenario
   - internal/dns/client.go: ExchangeRawUDP
   - internal/sysinfo/netinfo.go: DetectNetworkSummary, detectDefaultRouteInterface

4. Автовыбор интерфейса, gateway, provider DNS и учёт VPN
   - main.go: загрузка config.json и печать сетевой сводки
   - internal/sysinfo/netinfo.go: DetectNetworkSummary, detectBestInterface,
     DetectDefaultGatewayIPv4ForInterface, DetectProviderDNSIPv4ForInterface,
     NextHopIPv4, isTunnelInterface

5. Низкоуровневая упаковка пакетов
   - internal/arp/frame.go
   - internal/packet/packet.go
   - internal/dns/message.go

6. Unit tests
   - internal/dns/message_test.go
   - internal/packet/packet_test.go
