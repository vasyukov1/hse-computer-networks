# HW-04 MyDrive

MyDrive — многопользовательское файловое хранилище поверх TCP. Клиент синхронизирует локальную директорию с личной директорией пользователя на сервере, передаёт только нужные файлы и поддерживает два режима передачи: через пользовательский буфер и через DMA.

## Возможности

- собственный протокол поверх TCP с явным указанием длины сообщения;
- постоянный идентификатор клиента, который создаётся один раз и сохраняется в конфиге;
- сравнение файлов по имени, размеру и `SHA-256`;
- передача только отсутствующих и изменённых файлов;
- удаление на сервере файлов, которых уже нет у клиента;
- несколько одновременных соединений передачи;
- режим `dma` для прямой передачи `*os.File -> *net.TCPConn`;
- команда `measure` для сравнения режимов `buffered` и `dma`.

## Структура проекта

```text
HW-04/
├── cmd/
│   ├── client/main.go
│   └── server/main.go
├── config/
│   ├── client_config.json
│   └── server_config.json
├── demo/
├── internal/
│   ├── client/
│   ├── config/
│   ├── files/
│   ├── protocol/
│   └── server/
├── README.md
├── go.mod
├── report.pdf
└── report.typ
```

## Запуск сервера

```bash
cd HW-04
go run ./cmd/server -config ./config/server_config.json
```

## Запуск клиента

```bash
cd HW-04
go run ./cmd/client -config ./config/client_config.json
```

## Команды клиента

```text
sync
sync dma
sync buffered
measure
help
exit
```

## Конфиг клиента

```json
{
  "client_id": "",
  "sync_dir": "../demo/client_data",
  "server_host": "127.0.0.1",
  "server_port": 9090,
  "max_connections": 8,
  "transfer_mode": "dma",
  "buffer_size_bytes": 1048576
}
```

Пояснения:

- `client_id` можно оставить пустым при первом запуске;
- `max_connections` задаёт число одновременных соединений передачи;
- `transfer_mode` выбирает режим передачи по умолчанию;
- `buffer_size_bytes` используется в режиме `buffered`.
